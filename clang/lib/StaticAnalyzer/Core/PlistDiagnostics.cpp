//===--- PlistDiagnostics.cpp - Plist Diagnostics for Paths -----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defines the PlistDiagnostics object.
//
//===----------------------------------------------------------------------===//

#include "PlistDiagnostics.h"
#include "clang/Analysis/IssueHash.h"
#include "clang/Analysis/MacroExpansionContext.h"
#include "clang/Analysis/PathDiagnostic.h"
#include "clang/Basic/PlistSupport.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/Version.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Lex/TokenConcatenation.h"
#include "clang/Rewrite/Core/HTMLRewrite.h"
#include "clang/StaticAnalyzer/Core/PathDiagnosticConsumers.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Support/FileSystem.h"
#include <array>
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace markup;

//===----------------------------------------------------------------------===//
// Declarations of helper classes and functions for emitting bug reports in
// plist format.
//===----------------------------------------------------------------------===//

namespace {
/// The control flow graph bodies of one plist file, each once. The reports of
/// a translation unit often run through the same functions, and a body does
/// not depend on the path, so a constraint trace names its bodies by index
/// into this table and keeps only the part its path took.
class CFGTable {
  /// Keyed by the body as printed, which is also what the file holds.
  llvm::StringMap<unsigned> Index;
  llvm::SmallVector<StringRef, 0> Bodies;

public:
  unsigned add(const PathDiagnosticCFG &CFG);
  void print(raw_ostream &o) const;
};

  class PlistDiagnostics : public PathDiagnosticConsumer {
    PathDiagnosticConsumerOptions DiagOpts;
    const std::string OutputFile;
    const Preprocessor &PP;
    const cross_tu::CrossTranslationUnitContext &CTU;
    const MacroExpansionContext &MacroExpansions;
    const bool SupportsCrossFileDiagnostics;

    void printBugPath(llvm::raw_ostream &o, const FIDMap &FM,
                      const PathPieces &Path, ArrayRef<PathDiagnosticCFG> CFGs,
                      ArrayRef<PathDiagnosticSymbol> Symbols, CFGTable &Graphs);

  public:
    PlistDiagnostics(PathDiagnosticConsumerOptions DiagOpts,
                     const std::string &OutputFile, const Preprocessor &PP,
                     const cross_tu::CrossTranslationUnitContext &CTU,
                     const MacroExpansionContext &MacroExpansions,
                     bool supportsMultipleFiles);

    ~PlistDiagnostics() override {}

    void FlushDiagnosticsImpl(std::vector<const PathDiagnostic *> &Diags,
                              FilesMade *filesMade) override;

    StringRef getName() const override {
      return "PlistDiagnostics";
    }

    PathGenerationScheme getGenerationScheme() const override {
      return Extensive;
    }
    bool supportsLogicalOpControlFlow() const override { return true; }
    bool supportsCrossFileDiagnostics() const override {
      return SupportsCrossFileDiagnostics;
    }
  };
} // end anonymous namespace

namespace {

namespace {
/// One entry of a constraint snapshot list, as indices into the trace's
/// strings, except for the integer of a variable's smt_signed.
using TraceEntry = llvm::SmallVector<unsigned, 5>;
using TraceList = std::vector<TraceEntry>;
} // namespace

/// A helper class for emitting a single report.
class PlistPrinter {
  const FIDMap& FM;
  const Preprocessor &PP;
  const cross_tu::CrossTranslationUnitContext &CTU;
  const MacroExpansionContext &MacroExpansions;
  llvm::SmallVector<const PathDiagnosticMacroPiece *, 0> MacroPieces;
  /// Position of the next element in the path array.
  unsigned NextPathIndex = 0;
  llvm::SmallVector<std::pair<unsigned, PathDiagnosticConstraintSnapshotRef>, 0>
      ConstraintSteps;

public:
  PlistPrinter(const FIDMap &FM, const Preprocessor &PP,
               const cross_tu::CrossTranslationUnitContext &CTU,
               const MacroExpansionContext &MacroExpansions)
      : FM(FM), PP(PP), CTU(CTU), MacroExpansions(MacroExpansions) {}

  void ReportDiag(raw_ostream &o, const PathDiagnosticPiece& P) {
    ReportPiece(o, P, /*indent*/ 4, /*depth*/ 0, /*includeControlFlow*/ true);
  }

  /// Print the expansions of the collected macro pieces.
  ///
  /// Each time ReportDiag is called on a PathDiagnosticMacroPiece (or, if one
  /// is found through a call piece, etc), it's subpieces are reported, and the
  /// piece itself is collected. Call this function after the entire bugpath
  /// was reported.
  void ReportMacroExpansions(raw_ostream &o, unsigned indent);

  /// Print the constraint trace collected while the path was printed, which
  /// does not exist unless constraint snapshots were requested.
  void ReportConstraintTrace(raw_ostream &o, ArrayRef<PathDiagnosticCFG> CFGs,
                             ArrayRef<PathDiagnosticSymbol> Symbols,
                             CFGTable &Graphs, unsigned indent);

private:
  void ReportCFGs(raw_ostream &o, ArrayRef<PathDiagnosticCFG> CFGs,
                  CFGTable &Graphs, unsigned indent);

  using ExplodedNodeInfo = PathDiagnosticConstraintSnapshot::ExplodedNodeInfo;
  /// Lists each node the collected steps came from once, in path order, and
  /// each stack frame of those nodes once, after its parent.
  void collectExplodedNodes();
  void ReportExplodedNodes(raw_ostream &o, unsigned indent);
  /// The entries of \p Symbols that the listed nodes' snapshots mention: the
  /// atomic symbols, then the types of the symbolic expressions.
  void ReportSymbols(raw_ostream &o, ArrayRef<PathDiagnosticSymbol> Symbols,
                     unsigned indent);

  /// The lists of one snapshot, in the order the trace writes them.
  using TraceLists = std::array<TraceList, 4>;
  TraceLists makeTraceLists(const PathDiagnosticConstraintSnapshot &Snapshot);
  unsigned intern(StringRef String);
  void ReportStringTable(raw_ostream &o, unsigned indent);

  /// Every string the snapshots of this trace refer to, each once, so a
  /// symbol, range or SMT-LIB line that many snapshots repeat costs one
  /// index per use.
  llvm::StringMap<unsigned> StringIndex;
  llvm::SmallVector<StringRef, 0> Strings;

  /// The snapshot of each node, which is one per node.
  llvm::SmallVector<const PathDiagnosticConstraintSnapshot *, 0> ExplodedNodes;
  /// Keyed by the snapshot, which is one per node. Not by the node's ID: the
  /// exploded graph hands out the ID of the newest node again after it
  /// reclaims one, so two nodes on a long path can share it.
  llvm::DenseMap<const PathDiagnosticConstraintSnapshot *, unsigned>
      ExplodedNodeIndex;
  struct StackFrameEntry {
    const ExplodedNodeInfo::Frame *Frame;
    std::optional<unsigned> Parent;
  };
  llvm::SmallVector<StackFrameEntry, 0> StackFrames;
  llvm::DenseMap<int64_t, unsigned> StackFrameIndex;
  /// Index into StackFrames of each node's innermost frame.
  llvm::SmallVector<unsigned, 0> ExplodedNodeFrames;

  void ReportPiece(raw_ostream &o, const PathDiagnosticPiece &P,
                   unsigned indent, unsigned depth, bool includeControlFlow,
                   bool isKeyEvent = false) {
    switch (P.getKind()) {
      case PathDiagnosticPiece::ControlFlow:
        if (includeControlFlow)
          ReportControlFlow(o, cast<PathDiagnosticControlFlowPiece>(P), indent);
        break;
      case PathDiagnosticPiece::Call:
        ReportCall(o, cast<PathDiagnosticCallPiece>(P), indent,
                   depth);
        break;
      case PathDiagnosticPiece::Event:
        ReportEvent(o, cast<PathDiagnosticEventPiece>(P), indent, depth,
                    isKeyEvent);
        break;
      case PathDiagnosticPiece::Macro:
        ReportMacroSubPieces(o, cast<PathDiagnosticMacroPiece>(P), indent,
                             depth);
        break;
      case PathDiagnosticPiece::Note:
        ReportNote(o, cast<PathDiagnosticNotePiece>(P), indent);
        break;
      case PathDiagnosticPiece::PopUp:
        ReportPopUp(o, cast<PathDiagnosticPopUpPiece>(P), indent);
        break;
    }
  }

  void EmitRanges(raw_ostream &o, const ArrayRef<SourceRange> Ranges,
                  unsigned indent);
  void EmitMessage(raw_ostream &o, StringRef Message, unsigned indent);
  void EmitFixits(raw_ostream &o, ArrayRef<FixItHint> fixits, unsigned indent);

  void ReportControlFlow(raw_ostream &o,
                         const PathDiagnosticControlFlowPiece& P,
                         unsigned indent);
  void ReportEvent(raw_ostream &o, const PathDiagnosticEventPiece& P,
                   unsigned indent, unsigned depth, bool isKeyEvent = false);
  void ReportCall(raw_ostream &o, const PathDiagnosticCallPiece &P,
                  unsigned indent, unsigned depth);
  void ReportMacroSubPieces(raw_ostream &o, const PathDiagnosticMacroPiece& P,
                            unsigned indent, unsigned depth);
  void ReportNote(raw_ostream &o, const PathDiagnosticNotePiece& P,
                  unsigned indent);

  void ReportPopUp(raw_ostream &o, const PathDiagnosticPopUpPiece &P,
                   unsigned indent);
};

} // end of anonymous namespace

/// Print coverage information to output stream @c o.
/// May modify the used list of files @c Fids by inserting new ones.
static void printCoverage(const PathDiagnostic *D,
                          unsigned InputIndentLevel,
                          SmallVectorImpl<FileID> &Fids,
                          FIDMap &FM,
                          llvm::raw_fd_ostream &o);

static std::optional<StringRef> getExpandedMacro(
    SourceLocation MacroLoc, const cross_tu::CrossTranslationUnitContext &CTU,
    const MacroExpansionContext &MacroExpansions, const SourceManager &SM);

//===----------------------------------------------------------------------===//
// Methods of PlistPrinter.
//===----------------------------------------------------------------------===//

void PlistPrinter::EmitRanges(raw_ostream &o,
                              const ArrayRef<SourceRange> Ranges,
                              unsigned indent) {

  if (Ranges.empty())
    return;

  Indent(o, indent) << "<key>ranges</key>\n";
  Indent(o, indent) << "<array>\n";
  ++indent;

  const SourceManager &SM = PP.getSourceManager();
  const LangOptions &LangOpts = PP.getLangOpts();

  for (auto &R : Ranges)
    EmitRange(o, SM,
              Lexer::getAsCharRange(SM.getExpansionRange(R), SM, LangOpts),
              FM, indent + 1);
  --indent;
  Indent(o, indent) << "</array>\n";
}

void PlistPrinter::EmitMessage(raw_ostream &o, StringRef Message,
                               unsigned indent) {
  // Output the text.
  assert(!Message.empty());
  Indent(o, indent) << "<key>extended_message</key>\n";
  Indent(o, indent);
  EmitString(o, Message) << '\n';

  // Output the short text.
  // FIXME: Really use a short string.
  Indent(o, indent) << "<key>message</key>\n";
  Indent(o, indent);
  EmitString(o, Message) << '\n';
}

void PlistPrinter::EmitFixits(raw_ostream &o, ArrayRef<FixItHint> fixits,
                              unsigned indent) {
  if (fixits.size() == 0)
    return;

  const SourceManager &SM = PP.getSourceManager();
  const LangOptions &LangOpts = PP.getLangOpts();

  Indent(o, indent) << "<key>fixits</key>\n";
  Indent(o, indent) << "<array>\n";
  for (const auto &fixit : fixits) {
    assert(!fixit.isNull());
    // FIXME: Add support for InsertFromRange and BeforePreviousInsertion.
    assert(!fixit.InsertFromRange.isValid() && "Not implemented yet!");
    assert(!fixit.BeforePreviousInsertions && "Not implemented yet!");
    Indent(o, indent) << " <dict>\n";
    Indent(o, indent) << "  <key>remove_range</key>\n";
    EmitRange(o, SM, Lexer::getAsCharRange(fixit.RemoveRange, SM, LangOpts),
              FM, indent + 2);
    Indent(o, indent) << "  <key>insert_string</key>";
    EmitString(o, fixit.CodeToInsert);
    o << "\n";
    Indent(o, indent) << " </dict>\n";
  }
  Indent(o, indent) << "</array>\n";
}

void PlistPrinter::ReportControlFlow(raw_ostream &o,
                                     const PathDiagnosticControlFlowPiece& P,
                                     unsigned indent) {

  const SourceManager &SM = PP.getSourceManager();
  const LangOptions &LangOpts = PP.getLangOpts();

  if (const PathDiagnosticConstraintSnapshotRef &Snapshot =
          P.getConstraintSnapshot())
    ConstraintSteps.emplace_back(NextPathIndex, Snapshot);
  ++NextPathIndex;

  Indent(o, indent) << "<dict>\n";
  ++indent;

  Indent(o, indent) << "<key>kind</key><string>control</string>\n";

  // Emit edges.
  Indent(o, indent) << "<key>edges</key>\n";
  ++indent;
  Indent(o, indent) << "<array>\n";
  ++indent;
  for (PathDiagnosticControlFlowPiece::const_iterator I=P.begin(), E=P.end();
       I!=E; ++I) {
    Indent(o, indent) << "<dict>\n";
    ++indent;

    // Make the ranges of the start and end point self-consistent with adjacent edges
    // by forcing to use only the beginning of the range.  This simplifies the layout
    // logic for clients.
    Indent(o, indent) << "<key>start</key>\n";
    SourceRange StartEdge(
        SM.getExpansionLoc(I->getStart().asRange().getBegin()));
    EmitRange(o, SM, Lexer::getAsCharRange(StartEdge, SM, LangOpts), FM,
              indent + 1);

    Indent(o, indent) << "<key>end</key>\n";
    SourceRange EndEdge(SM.getExpansionLoc(I->getEnd().asRange().getBegin()));
    EmitRange(o, SM, Lexer::getAsCharRange(EndEdge, SM, LangOpts), FM,
              indent + 1);

    --indent;
    Indent(o, indent) << "</dict>\n";
  }
  --indent;
  Indent(o, indent) << "</array>\n";
  --indent;

  // Output any helper text.
  const auto &s = P.getString();
  if (!s.empty()) {
    Indent(o, indent) << "<key>alternate</key>";
    EmitString(o, s) << '\n';
  }

  assert(P.getFixits().size() == 0 &&
         "Fixits on constrol flow pieces are not implemented yet!");

  --indent;
  Indent(o, indent) << "</dict>\n";
}

void PlistPrinter::ReportEvent(raw_ostream &o, const PathDiagnosticEventPiece& P,
                               unsigned indent, unsigned depth,
                               bool isKeyEvent) {

  const SourceManager &SM = PP.getSourceManager();

  if (const PathDiagnosticConstraintSnapshotRef &Snapshot =
          P.getConstraintSnapshot())
    ConstraintSteps.emplace_back(NextPathIndex, Snapshot);
  ++NextPathIndex;

  Indent(o, indent) << "<dict>\n";
  ++indent;

  Indent(o, indent) << "<key>kind</key><string>event</string>\n";

  if (isKeyEvent) {
    Indent(o, indent) << "<key>key_event</key><true/>\n";
  }

  // Output the location.
  FullSourceLoc L = P.getLocation().asLocation();

  Indent(o, indent) << "<key>location</key>\n";
  EmitLocation(o, SM, L, FM, indent);

  // Output the ranges (if any).
  ArrayRef<SourceRange> Ranges = P.getRanges();
  EmitRanges(o, Ranges, indent);

  // Output the call depth.
  Indent(o, indent) << "<key>depth</key>";
  EmitInteger(o, depth) << '\n';

  // Output the text.
  EmitMessage(o, P.getString(), indent);

  // Output the fixits.
  EmitFixits(o, P.getFixits(), indent);

  // Finish up.
  --indent;
  Indent(o, indent); o << "</dict>\n";
}

void PlistPrinter::ReportCall(raw_ostream &o, const PathDiagnosticCallPiece &P,
                              unsigned indent,
                              unsigned depth) {

  if (auto callEnter = P.getCallEnterEvent())
    ReportPiece(o, *callEnter, indent, depth, /*includeControlFlow*/ true,
                P.isLastInMainSourceFile());


  ++depth;

  if (auto callEnterWithinCaller = P.getCallEnterWithinCallerEvent())
    ReportPiece(o, *callEnterWithinCaller, indent, depth,
                /*includeControlFlow*/ true);

  for (PathPieces::const_iterator I = P.path.begin(), E = P.path.end();I!=E;++I)
    ReportPiece(o, **I, indent, depth, /*includeControlFlow*/ true);

  --depth;

  if (auto callExit = P.getCallExitEvent())
    ReportPiece(o, *callExit, indent, depth, /*includeControlFlow*/ true);

  assert(P.getFixits().size() == 0 &&
         "Fixits on call pieces are not implemented yet!");
}

void PlistPrinter::ReportMacroSubPieces(raw_ostream &o,
                                        const PathDiagnosticMacroPiece& P,
                                        unsigned indent, unsigned depth) {
  MacroPieces.push_back(&P);

  for (const auto &SubPiece : P.subPieces) {
    ReportPiece(o, *SubPiece, indent, depth, /*includeControlFlow*/ false);
  }

  assert(P.getFixits().size() == 0 &&
         "Fixits on constrol flow pieces are not implemented yet!");
}

void PlistPrinter::ReportMacroExpansions(raw_ostream &o, unsigned indent) {

  for (const PathDiagnosticMacroPiece *P : MacroPieces) {
    const SourceManager &SM = PP.getSourceManager();

    SourceLocation MacroExpansionLoc =
        P->getLocation().asLocation().getExpansionLoc();

    const std::optional<StringRef> MacroName =
        MacroExpansions.getOriginalText(MacroExpansionLoc);
    const std::optional<StringRef> ExpansionText =
        getExpandedMacro(MacroExpansionLoc, CTU, MacroExpansions, SM);

    if (!MacroName || !ExpansionText)
      continue;

    Indent(o, indent) << "<dict>\n";
    ++indent;

    // Output the location.
    FullSourceLoc L = P->getLocation().asLocation();

    Indent(o, indent) << "<key>location</key>\n";
    EmitLocation(o, SM, L, FM, indent);

    // Output the ranges (if any).
    ArrayRef<SourceRange> Ranges = P->getRanges();
    EmitRanges(o, Ranges, indent);

    // Output the macro name.
    Indent(o, indent) << "<key>name</key>";
    EmitString(o, *MacroName) << '\n';

    // Output what it expands into.
    Indent(o, indent) << "<key>expansion</key>";
    EmitString(o, *ExpansionText) << '\n';

    // Finish up.
    --indent;
    Indent(o, indent);
    o << "</dict>\n";
  }
}

static StringRef
toString(PathDiagnosticConstraintSnapshot::Variable::ValueKind Kind) {
  using ValueKind = PathDiagnosticConstraintSnapshot::Variable::ValueKind;
  switch (Kind) {
  case ValueKind::Symbol:
    return "symbol";
  case ValueKind::Integer:
    return "integer";
  case ValueKind::Address:
    return "address";
  }
  llvm_unreachable("unknown variable value kind");
}

/// The keys under which a node's snapshot lists are written, in the order of
/// PlistPrinter::TraceLists.
static constexpr StringRef TraceListKeys[] = {
    "symbol_ranges", "variables", "path_condition", "smt_declarations"};

namespace {
/// How one snapshot list turns into the next one's. Positions in Replace and
/// Remove are in the earlier list, and positions in Insert in the later one,
/// so applying Replace, then Remove, then Insert in ascending order of
/// position gives the later list.
struct TraceListDelta {
  llvm::SmallVector<std::pair<unsigned, const TraceEntry *>, 0> Replace;
  llvm::SmallVector<unsigned, 0> Remove;
  llvm::SmallVector<std::pair<unsigned, const TraceEntry *>, 0> Insert;

  bool empty() const {
    return Replace.empty() && Remove.empty() && Insert.empty();
  }
};
} // namespace

/// An entry is identified by its first index (the symbol of a range, the
/// name of a variable, the line of a declaration), and both lists are sorted
/// the same way, so entries kept from one snapshot to the next stay in order.
/// When that does not hold, the delta lists the whole later list.
static TraceListDelta diffTraceLists(const TraceList &Prev,
                                     const TraceList &Next) {
  TraceListDelta Delta;
  llvm::DenseMap<unsigned, unsigned> NextByKey;
  bool Keyed = true;
  for (auto [Index, Entry] : llvm::enumerate(Next))
    Keyed &= NextByKey.try_emplace(Entry.front(), Index).second;

  llvm::SmallVector<bool, 0> Kept(Next.size(), false);
  std::optional<unsigned> LastKept;
  for (auto [Index, Entry] : llvm::enumerate(Prev)) {
    if (!Keyed)
      break;
    auto It = NextByKey.find(Entry.front());
    if (It == NextByKey.end() || Kept[It->second]) {
      Delta.Remove.push_back(Index);
      continue;
    }
    if (LastKept && It->second < *LastKept) {
      Keyed = false;
      break;
    }
    LastKept = It->second;
    Kept[It->second] = true;
    if (Next[It->second] != Entry)
      Delta.Replace.emplace_back(Index, &Next[It->second]);
  }

  if (!Keyed) {
    Delta = TraceListDelta();
    Kept.assign(Next.size(), false);
    for (unsigned Index = 0; Index < Prev.size(); ++Index)
      Delta.Remove.push_back(Index);
  }
  for (auto [Index, Entry] : llvm::enumerate(Next))
    if (!Kept[Index])
      Delta.Insert.emplace_back(Index, &Entry);
  return Delta;
}

[[maybe_unused]] static TraceList
applyTraceListDelta(TraceList List, const TraceListDelta &Delta) {
  for (auto [Index, Entry] : Delta.Replace)
    List[Index] = *Entry;
  for (unsigned Index : llvm::reverse(Delta.Remove))
    List.erase(List.begin() + Index);
  for (auto [Index, Entry] : Delta.Insert)
    List.insert(List.begin() + Index, *Entry);
  return List;
}

/// An operation is written on one line, as its position followed by the
/// entry, so a long path costs a few lines per snapshot.
static void ReportTraceListDelta(raw_ostream &o, StringRef Key,
                                 const TraceListDelta &Delta, unsigned indent) {
  if (Delta.empty())
    return;
  auto ReportOperations = [&](StringRef Name, const auto &Operations) {
    if (Operations.empty())
      return;
    Indent(o, indent + 1) << "<key>" << Name << "</key>\n";
    Indent(o, indent + 1) << "<array>\n";
    for (const auto &[Index, Entry] : Operations) {
      Indent(o, indent + 2) << "<array>";
      EmitInteger(o, Index);
      for (unsigned Value : *Entry)
        EmitInteger(o, Value);
      o << "</array>\n";
    }
    Indent(o, indent + 1) << "</array>\n";
  };

  Indent(o, indent) << "<key>" << Key << "</key>\n";
  Indent(o, indent) << "<dict>\n";
  ReportOperations("replace", Delta.Replace);
  if (!Delta.Remove.empty()) {
    Indent(o, indent + 1) << "<key>remove</key>\n";
    Indent(o, indent + 1) << "<array>";
    for (unsigned Index : Delta.Remove)
      EmitInteger(o, Index);
    o << "</array>\n";
  }
  ReportOperations("insert", Delta.Insert);
  Indent(o, indent) << "</dict>\n";
}

unsigned PlistPrinter::intern(StringRef String) {
  auto [It, Inserted] = StringIndex.try_emplace(String, Strings.size());
  if (Inserted)
    Strings.push_back(It->getKey());
  return It->second;
}

PlistPrinter::TraceLists
PlistPrinter::makeTraceLists(const PathDiagnosticConstraintSnapshot &Snapshot) {
  TraceLists Lists;
  auto &[Ranges, Variables, PathCondition, Declarations] = Lists;
  for (const auto &[Symbol, Range] : Snapshot.SymbolRanges)
    Ranges.push_back({intern(Symbol), intern(Range)});
  for (const PathDiagnosticConstraintSnapshot::Variable &Var :
       Snapshot.Variables) {
    TraceEntry &Entry = Variables.emplace_back(TraceEntry{
        intern(Var.Name), intern(Var.Value), intern(toString(Var.Kind))});
    if (!Var.SMTTerm.empty())
      Entry.append({intern(Var.SMTTerm), Var.SMTSigned});
  }
  // There is one assertion per path condition entry, in the same order, so
  // an entry carries its assertion along.
  assert(!Snapshot.HasSMTLIB ||
         Snapshot.SMTAssertions.size() == Snapshot.PathCondition.size());
  for (auto [Index, Constraint] : llvm::enumerate(Snapshot.PathCondition)) {
    TraceEntry &Entry = PathCondition.emplace_back(
        TraceEntry{intern(Constraint.Symbol), intern(Constraint.Range)});
    if (Snapshot.HasSMTLIB)
      Entry.push_back(intern(Snapshot.SMTAssertions[Index]));
  }
  for (const std::string &Declaration : Snapshot.SMTDeclarations)
    Declarations.push_back({intern(Declaration)});
  return Lists;
}

void PlistPrinter::ReportStringTable(raw_ostream &o, unsigned indent) {
  Indent(o, indent) << "<key>strings</key>\n";
  Indent(o, indent) << "<array>\n";
  for (StringRef String : Strings) {
    Indent(o, indent + 1);
    EmitString(o, String) << '\n';
  }
  Indent(o, indent) << "</array>\n";
}

static void printCFGBody(raw_ostream &o, const PathDiagnosticCFG &CFG,
                         unsigned indent) {
  // Blocks and elements are arrays rather than dicts, because the keys of
  // every subexpression would make up a third of the graph's size.
  Indent(o, indent) << "<dict>\n";
  ++indent;
  Indent(o, indent) << "<key>function</key>";
  EmitString(o, CFG.Function) << '\n';
  Indent(o, indent) << "<key>entry</key>";
  EmitInteger(o, CFG.EntryID) << '\n';
  Indent(o, indent) << "<key>exit</key>";
  EmitInteger(o, CFG.ExitID) << '\n';
  Indent(o, indent) << "<key>blocks</key>\n";
  Indent(o, indent) << "<array>\n";
  ++indent;
  for (const PathDiagnosticCFG::Block &Block : CFG.Blocks) {
    Indent(o, indent) << "<array>\n";
    Indent(o, indent + 1);
    EmitInteger(o, Block.ID) << '\n';
    Indent(o, indent + 1);
    EmitString(o, Block.Terminator) << '\n';
    Indent(o, indent + 1) << "<array>";
    for (std::optional<unsigned> Succ : Block.Successors)
      EmitInteger(o, Succ ? int64_t(*Succ) : -1);
    o << "</array>\n";
    Indent(o, indent + 1) << "<array>";
    for (const PathDiagnosticCFG::Element &Elem : Block.Elements) {
      o << '\n';
      Indent(o, indent + 2) << "<array>";
      EmitString(o, Elem.Text);
      EmitInteger(o, Elem.Line);
      EmitInteger(o, Elem.Parent ? int64_t(*Elem.Parent) : -1);
      o << "</array>";
    }
    if (!Block.Elements.empty())
      Indent(o << '\n', indent + 1);
    o << "</array>\n";
    Indent(o, indent) << "</array>\n";
  }
  --indent;
  Indent(o, indent) << "</array>\n";
  --indent;
  Indent(o, indent) << "</dict>\n";
}

unsigned CFGTable::add(const PathDiagnosticCFG &CFG) {
  std::string Body;
  llvm::raw_string_ostream OS(Body);
  // At the depth of the file's table, so a body is printed once.
  printCFGBody(OS, CFG, /*indent=*/2);
  auto [It, Inserted] = Index.try_emplace(Body, Bodies.size());
  if (Inserted)
    Bodies.push_back(It->getKey());
  return It->second;
}

void CFGTable::print(raw_ostream &o) const {
  if (Bodies.empty())
    return;
  o << " <key>constraint_trace_cfgs</key>\n";
  o << " <array>\n";
  for (StringRef Body : Bodies)
    o << Body;
  o << " </array>\n";
}

void PlistPrinter::ReportCFGs(raw_ostream &o, ArrayRef<PathDiagnosticCFG> CFGs,
                              CFGTable &Graphs, unsigned indent) {
  Indent(o, indent) << "<key>cfgs</key>\n";
  Indent(o, indent) << "<array>\n";
  ++indent;
  for (const PathDiagnosticCFG &CFG : CFGs) {
    Indent(o, indent) << "<dict>\n";
    ++indent;
    Indent(o, indent) << "<key>graph</key>";
    EmitInteger(o, Graphs.add(CFG)) << '\n';
    Indent(o, indent) << "<key>path_blocks</key>\n";
    Indent(o, indent) << "<array>";
    for (unsigned ID : CFG.PathBlocks)
      EmitInteger(o, ID);
    o << "</array>\n";
    Indent(o, indent) << "<key>path_edges</key>\n";
    Indent(o, indent) << "<array>";
    for (auto [From, To] : CFG.PathEdges) {
      EmitInteger(o, From);
      EmitInteger(o, To);
    }
    o << "</array>\n";
    --indent;
    Indent(o, indent) << "</dict>\n";
  }
  --indent;
  Indent(o, indent) << "</array>\n";
}

void PlistPrinter::collectExplodedNodes() {
  for (const auto &[PathIndex, Snapshot] : ConstraintSteps) {
    // Every snapshot is built from a node, and a node has one snapshot.
    assert(Snapshot->Node && "constraint snapshot without its node");
    if (ExplodedNodeIndex.try_emplace(Snapshot.get(), 0).second)
      ExplodedNodes.push_back(Snapshot.get());
  }
  llvm::sort(ExplodedNodes, [](const PathDiagnosticConstraintSnapshot *L,
                               const PathDiagnosticConstraintSnapshot *R) {
    return L->Node->PathPosition < R->Node->PathPosition;
  });

  for (auto [I, Snapshot] : llvm::enumerate(ExplodedNodes)) {
    ExplodedNodeIndex[Snapshot] = I;
    std::optional<unsigned> Parent;
    for (const ExplodedNodeInfo::Frame &Frame :
         llvm::reverse(Snapshot->Node->Stack)) {
      auto [It, Inserted] =
          StackFrameIndex.try_emplace(Frame.ID, StackFrames.size());
      if (Inserted)
        StackFrames.push_back({&Frame, Parent});
      Parent = It->second;
    }
    ExplodedNodeFrames.push_back(*Parent);
  }
}

void PlistPrinter::ReportExplodedNodes(raw_ostream &o, unsigned indent) {
  const SourceManager &SM = PP.getSourceManager();

  // The nodes are the snapshot table: each node's snapshot is written as the
  // change from the previous node's, which is linear in the path length where
  // whole snapshots would be quadratic.
  TraceLists Prev;
  Indent(o, indent) << "<key>exploded_nodes</key>\n";
  Indent(o, indent) << "<array>\n";
  ++indent;
  for (auto [Snapshot, Frame] :
       llvm::zip_equal(ExplodedNodes, ExplodedNodeFrames)) {
    const ExplodedNodeInfo &Node = *Snapshot->Node;
    Indent(o, indent) << "<dict>\n";
    ++indent;
    Indent(o, indent) << "<key>id</key>";
    EmitInteger(o, Node.NodeID) << '\n';
    Indent(o, indent) << "<key>state_id</key>";
    EmitInteger(o, Node.StateID) << '\n';
    Indent(o, indent) << "<key>path_position</key>";
    EmitInteger(o, Node.PathPosition) << '\n';
    Indent(o, indent) << "<key>kind</key>";
    EmitString(o, Node.Kind) << '\n';
    if (Node.Location.isValid()) {
      Indent(o, indent) << "<key>location</key>\n";
      EmitLocation(o, SM, Node.Location, FM, indent);
    }
    Indent(o, indent) << "<key>frame</key>";
    EmitInteger(o, Frame) << '\n';
    if (const auto &Position = Snapshot->Position) {
      Indent(o, indent) << "<key>cfg_position</key>\n";
      Indent(o, indent) << "<dict>\n";
      Indent(o, indent + 1) << "<key>cfg</key>";
      EmitInteger(o, Position->CFGIndex) << '\n';
      Indent(o, indent + 1) << "<key>block</key>";
      EmitInteger(o, Position->BlockID) << '\n';
      if (Position->Element) {
        Indent(o, indent + 1) << "<key>element</key>";
        EmitInteger(o, *Position->Element) << '\n';
      } else if (Position->AtTerminator) {
        Indent(o, indent + 1) << "<key>terminator</key><true/>\n";
      }
      Indent(o, indent) << "</dict>\n";
    }
    assert(Snapshot->HasSMTLIB == ExplodedNodes.front()->HasSMTLIB);
    TraceLists Next = makeTraceLists(*Snapshot);
    for (auto [Key, PrevList, NextList] :
         llvm::zip_equal(TraceListKeys, Prev, Next)) {
      TraceListDelta Delta = diffTraceLists(PrevList, NextList);
      assert(applyTraceListDelta(PrevList, Delta) == NextList &&
             "a snapshot delta does not give the snapshot");
      ReportTraceListDelta(o, Key, Delta, indent);
    }
    Prev = std::move(Next);
    --indent;
    Indent(o, indent) << "</dict>\n";
  }
  --indent;
  Indent(o, indent) << "</array>\n";

  Indent(o, indent) << "<key>stack_frames</key>\n";
  Indent(o, indent) << "<array>\n";
  ++indent;
  for (const StackFrameEntry &Entry : StackFrames) {
    Indent(o, indent) << "<dict>\n";
    ++indent;
    Indent(o, indent) << "<key>function</key>";
    EmitString(o, Entry.Frame->Function) << '\n';
    if (Entry.Parent) {
      Indent(o, indent) << "<key>parent</key>";
      EmitInteger(o, *Entry.Parent) << '\n';
    }
    if (Entry.Frame->CallSite.isValid()) {
      Indent(o, indent) << "<key>call_site</key>\n";
      EmitLocation(o, SM, Entry.Frame->CallSite, FM, indent);
    }
    --indent;
    Indent(o, indent) << "</dict>\n";
  }
  --indent;
  Indent(o, indent) << "</array>\n";
}

static StringRef toString(PathDiagnosticSymbol::Kind SymbolKind) {
  using Kind = PathDiagnosticSymbol::Kind;
  switch (SymbolKind) {
  case Kind::RegionValue:
    return "region_value";
  case Kind::Conjured:
    return "conjured";
  case Kind::Derived:
    return "derived";
  case Kind::Metadata:
    return "metadata";
  case Kind::Extent:
    return "extent";
  case Kind::Expression:
    break;
  }
  llvm_unreachable("an expression has no kind in the trace");
}

static StringRef toString(PathDiagnosticSymbol::Reason Why) {
  using Reason = PathDiagnosticSymbol::Reason;
  switch (Why) {
  case Reason::CallResult:
    return "call_result";
  case Reason::Invalidation:
    return "invalidation";
  case Reason::LoopWidening:
    return "loop_widening";
  case Reason::Other:
    return "other";
  }
  llvm_unreachable("unknown conjured symbol reason");
}

void PlistPrinter::ReportSymbols(raw_ostream &o,
                                 ArrayRef<PathDiagnosticSymbol> Symbols,
                                 unsigned indent) {
  std::vector<unsigned> Listed;
  for (const PathDiagnosticConstraintSnapshot *Snapshot : ExplodedNodes)
    llvm::append_range(Listed, Snapshot->Symbols);
  if (Listed.empty())
    return;
  // In the order of the snapshot lists, which are sorted by dump.
  llvm::sort(Listed, [Symbols](unsigned L, unsigned R) {
    return Symbols[L].Symbol < Symbols[R].Symbol;
  });
  Listed.erase(llvm::unique(Listed), Listed.end());
  // Every expression has atoms, so the atoms' list is never empty.
  auto Expressions = std::stable_partition(
      Listed.begin(), Listed.end(), [Symbols](unsigned I) {
        return Symbols[I].SymbolKind != PathDiagnosticSymbol::Kind::Expression;
      });

  const SourceManager &SM = PP.getSourceManager();
  Indent(o, indent) << "<key>symbols</key>\n";
  Indent(o, indent) << "<array>\n";
  ++indent;
  for (unsigned Index : llvm::make_range(Listed.begin(), Expressions)) {
    const PathDiagnosticSymbol &Sym = Symbols[Index];
    Indent(o, indent) << "<dict>\n";
    ++indent;
    Indent(o, indent) << "<key>symbol</key>";
    EmitInteger(o, intern(Sym.Symbol)) << '\n';
    Indent(o, indent) << "<key>kind</key>";
    EmitString(o, toString(Sym.SymbolKind)) << '\n';
    if (!Sym.Parent.empty()) {
      Indent(o, indent) << "<key>parent</key>";
      EmitInteger(o, intern(Sym.Parent)) << '\n';
    }
    if (!Sym.Region.empty()) {
      Indent(o, indent) << "<key>region</key>";
      EmitInteger(o, intern(Sym.Region)) << '\n';
    }
    if (!Sym.Name.empty()) {
      Indent(o, indent) << "<key>name</key>";
      EmitInteger(o, intern(Sym.Name)) << '\n';
    }
    if (!Sym.Type.empty()) {
      Indent(o, indent) << "<key>type</key>";
      EmitInteger(o, intern(Sym.Type)) << '\n';
    }
    if (Sym.IsPointer)
      Indent(o, indent) << "<key>pointer</key><true/>\n";
    if (!Sym.SMTTerm.empty()) {
      Indent(o, indent) << "<key>smt</key>";
      EmitInteger(o, intern(Sym.SMTTerm)) << '\n';
      Indent(o, indent) << "<key>smt_signed</key>"
                        << (Sym.SMTSigned ? "<true/>" : "<false/>") << '\n';
    }
    if (const auto &Origin = Sym.Conjured) {
      Indent(o, indent) << "<key>origin</key>\n";
      Indent(o, indent) << "<dict>\n";
      ++indent;
      Indent(o, indent) << "<key>reason</key>";
      EmitString(o, toString(Origin->Why)) << '\n';
      if (!Origin->Statement.empty()) {
        Indent(o, indent) << "<key>statement</key>";
        EmitInteger(o, intern(Origin->Statement)) << '\n';
      }
      if (Origin->Location.isValid()) {
        Indent(o, indent) << "<key>location</key>\n";
        EmitLocation(o, SM, Origin->Location, FM, indent);
      }
      if (!Origin->Callee.empty()) {
        Indent(o, indent) << "<key>callee</key>";
        EmitInteger(o, intern(Origin->Callee)) << '\n';
      }
      if (Origin->Globals)
        Indent(o, indent) << "<key>globals</key><true/>\n";
      if (!Origin->Region.empty()) {
        Indent(o, indent) << "<key>region</key>";
        EmitInteger(o, intern(Origin->Region)) << '\n';
      }
      if (Origin->Loop.isValid()) {
        Indent(o, indent) << "<key>loop</key>\n";
        EmitLocation(o, SM, Origin->Loop, FM, indent);
      }
      Indent(o, indent) << "<key>function</key>";
      EmitInteger(o, intern(Origin->Function)) << '\n';
      // A frame the path only passed through, such as a call the diagnostic
      // pruned, has no entry in stack_frames.
      if (auto Frame = StackFrameIndex.find(Origin->FrameID);
          Frame != StackFrameIndex.end()) {
        Indent(o, indent) << "<key>frame</key>";
        EmitInteger(o, Frame->second) << '\n';
      }
      --indent;
      Indent(o, indent) << "</dict>\n";
    }
    --indent;
    Indent(o, indent) << "</dict>\n";
  }
  --indent;
  Indent(o, indent) << "</array>\n";

  if (Expressions == Listed.end())
    return;
  Indent(o, indent) << "<key>expressions</key>\n";
  Indent(o, indent) << "<array>\n";
  ++indent;
  for (unsigned Index : llvm::make_range(Expressions, Listed.end())) {
    const PathDiagnosticSymbol &Expression = Symbols[Index];
    Indent(o, indent) << "<dict>\n";
    ++indent;
    Indent(o, indent) << "<key>symbol</key>";
    EmitInteger(o, intern(Expression.Symbol)) << '\n';
    if (!Expression.Type.empty()) {
      Indent(o, indent) << "<key>type</key>";
      EmitInteger(o, intern(Expression.Type)) << '\n';
    }
    if (Expression.IsPointer)
      Indent(o, indent) << "<key>pointer</key><true/>\n";
    --indent;
    Indent(o, indent) << "</dict>\n";
  }
  --indent;
  Indent(o, indent) << "</array>\n";
}

void PlistPrinter::ReportConstraintTrace(raw_ostream &o,
                                         ArrayRef<PathDiagnosticCFG> CFGs,
                                         ArrayRef<PathDiagnosticSymbol> Symbols,
                                         CFGTable &Graphs, unsigned indent) {
  if (ConstraintSteps.empty())
    return;

  collectExplodedNodes();
  Indent(o, indent) << "<key>constraint_trace</key>\n";
  Indent(o, indent) << "<dict>\n";
  ++indent;
  Indent(o, indent) << "<key>version</key>";
  EmitInteger(o, 2) << '\n';
  // Every snapshot of a report comes from the same Clang, so either all of
  // them have SMT-LIB or none does.
  if (ExplodedNodes.front()->HasSMTLIB)
    Indent(o, indent) << "<key>smtlib</key><true/>\n";
  Indent(o, indent) << "<key>steps</key>\n";
  Indent(o, indent) << "<array>\n";
  ++indent;
  for (const auto &[PathIndex, Snapshot] : ConstraintSteps) {
    Indent(o, indent) << "<dict>\n";
    Indent(o, indent + 1) << "<key>path_index</key>";
    EmitInteger(o, PathIndex) << '\n';
    Indent(o, indent + 1) << "<key>exploded_node</key>";
    EmitInteger(o, ExplodedNodeIndex.find(Snapshot.get())->second) << '\n';
    Indent(o, indent) << "</dict>\n";
  }
  --indent;
  Indent(o, indent) << "</array>\n";
  // Once per diagnostic rather than per step, because a CFG is shared by
  // every step in its function.
  if (!CFGs.empty())
    ReportCFGs(o, CFGs, Graphs, indent);
  ReportExplodedNodes(o, indent);
  ReportSymbols(o, Symbols, indent);
  ReportStringTable(o, indent);
  --indent;
  Indent(o, indent) << "</dict>\n";
}

void PlistPrinter::ReportNote(raw_ostream &o, const PathDiagnosticNotePiece& P,
                              unsigned indent) {

  const SourceManager &SM = PP.getSourceManager();

  Indent(o, indent) << "<dict>\n";
  ++indent;

  // Output the location.
  FullSourceLoc L = P.getLocation().asLocation();

  Indent(o, indent) << "<key>location</key>\n";
  EmitLocation(o, SM, L, FM, indent);

  // Output the ranges (if any).
  ArrayRef<SourceRange> Ranges = P.getRanges();
  EmitRanges(o, Ranges, indent);

  // Output the text.
  EmitMessage(o, P.getString(), indent);

  // Output the fixits.
  EmitFixits(o, P.getFixits(), indent);

  // Finish up.
  --indent;
  Indent(o, indent); o << "</dict>\n";
}

void PlistPrinter::ReportPopUp(raw_ostream &o,
                               const PathDiagnosticPopUpPiece &P,
                               unsigned indent) {
  const SourceManager &SM = PP.getSourceManager();

  ++NextPathIndex;

  Indent(o, indent) << "<dict>\n";
  ++indent;

  Indent(o, indent) << "<key>kind</key><string>pop-up</string>\n";

  // Output the location.
  FullSourceLoc L = P.getLocation().asLocation();

  Indent(o, indent) << "<key>location</key>\n";
  EmitLocation(o, SM, L, FM, indent);

  // Output the ranges (if any).
  ArrayRef<SourceRange> Ranges = P.getRanges();
  EmitRanges(o, Ranges, indent);

  // Output the text.
  EmitMessage(o, P.getString(), indent);

  assert(P.getFixits().size() == 0 &&
         "Fixits on pop-up pieces are not implemented yet!");

  // Finish up.
  --indent;
  Indent(o, indent) << "</dict>\n";
}

//===----------------------------------------------------------------------===//
// Static function definitions.
//===----------------------------------------------------------------------===//

/// Print coverage information to output stream @c o.
/// May modify the used list of files @c Fids by inserting new ones.
static void printCoverage(const PathDiagnostic *D,
                          unsigned InputIndentLevel,
                          SmallVectorImpl<FileID> &Fids,
                          FIDMap &FM,
                          llvm::raw_fd_ostream &o) {
  unsigned IndentLevel = InputIndentLevel;

  Indent(o, IndentLevel) << "<key>ExecutedLines</key>\n";
  Indent(o, IndentLevel) << "<dict>\n";
  IndentLevel++;

  // Mapping from file IDs to executed lines.
  const FilesToLineNumsMap &ExecutedLines = D->getExecutedLines();
  for (const auto &[FID, Lines] : ExecutedLines) {
    unsigned FileKey = AddFID(FM, Fids, FID);
    Indent(o, IndentLevel) << "<key>" << FileKey << "</key>\n";
    Indent(o, IndentLevel) << "<array>\n";
    IndentLevel++;
    for (unsigned LineNo : Lines) {
      Indent(o, IndentLevel);
      EmitInteger(o, LineNo) << "\n";
    }
    IndentLevel--;
    Indent(o, IndentLevel) << "</array>\n";
  }
  IndentLevel--;
  Indent(o, IndentLevel) << "</dict>\n";

  assert(IndentLevel == InputIndentLevel);
}

//===----------------------------------------------------------------------===//
// Methods of PlistDiagnostics.
//===----------------------------------------------------------------------===//

PlistDiagnostics::PlistDiagnostics(
    PathDiagnosticConsumerOptions DiagOpts, const std::string &output,
    const Preprocessor &PP, const cross_tu::CrossTranslationUnitContext &CTU,
    const MacroExpansionContext &MacroExpansions, bool supportsMultipleFiles)
    : DiagOpts(std::move(DiagOpts)), OutputFile(output), PP(PP), CTU(CTU),
      MacroExpansions(MacroExpansions),
      SupportsCrossFileDiagnostics(supportsMultipleFiles) {
  // FIXME: Will be used by a later planned change.
  (void)this->CTU;
}

/// Creates and registers a Plist diagnostic consumer, without any additional
/// text consumer.
void ento::createPlistDiagnosticConsumerImpl(
    PathDiagnosticConsumerOptions DiagOpts, PathDiagnosticConsumers &C,
    const std::string &OutputFile, const Preprocessor &PP,
    const cross_tu::CrossTranslationUnitContext &CTU,
    const MacroExpansionContext &MacroExpansions, bool SupportsMultipleFiles) {

  // TODO: Emit an error here.
  if (OutputFile.empty())
    return;

  C.push_back(std::make_unique<PlistDiagnostics>(
      DiagOpts, OutputFile, PP, CTU, MacroExpansions, SupportsMultipleFiles));
}

void ento::createPlistDiagnosticConsumer(
    PathDiagnosticConsumerOptions DiagOpts, PathDiagnosticConsumers &C,
    const std::string &OutputFile, const Preprocessor &PP,
    const cross_tu::CrossTranslationUnitContext &CTU,
    const MacroExpansionContext &MacroExpansions) {

  createPlistDiagnosticConsumerImpl(DiagOpts, C, OutputFile, PP, CTU,
                                    MacroExpansions,
                                    /*SupportsMultipleFiles=*/false);
  createTextMinimalPathDiagnosticConsumer(std::move(DiagOpts), C, OutputFile,
                                          PP, CTU, MacroExpansions);
}

void ento::createPlistMultiFileDiagnosticConsumer(
    PathDiagnosticConsumerOptions DiagOpts, PathDiagnosticConsumers &C,
    const std::string &OutputFile, const Preprocessor &PP,
    const cross_tu::CrossTranslationUnitContext &CTU,
    const MacroExpansionContext &MacroExpansions) {

  createPlistDiagnosticConsumerImpl(DiagOpts, C, OutputFile, PP, CTU,
                                    MacroExpansions,
                                    /*SupportsMultipleFiles=*/true);

  createTextMinimalPathDiagnosticConsumer(std::move(DiagOpts), C, OutputFile,
                                          PP, CTU, MacroExpansions);
}

void PlistDiagnostics::printBugPath(llvm::raw_ostream &o, const FIDMap &FM,
                                    const PathPieces &Path,
                                    ArrayRef<PathDiagnosticCFG> CFGs,
                                    ArrayRef<PathDiagnosticSymbol> Symbols,
                                    CFGTable &Graphs) {
  PlistPrinter Printer(FM, PP, CTU, MacroExpansions);
  assert(std::is_partitioned(Path.begin(), Path.end(),
                             [](const PathDiagnosticPieceRef &E) {
                               return E->getKind() == PathDiagnosticPiece::Note;
                             }) &&
         "PathDiagnostic is not partitioned so that notes precede the rest");

  PathPieces::const_iterator FirstNonNote =
      llvm::partition_point(Path, [](const PathDiagnosticPieceRef &E) {
        return E->getKind() == PathDiagnosticPiece::Note;
      });

  PathPieces::const_iterator I = Path.begin();

  if (FirstNonNote != Path.begin()) {
    o << "   <key>notes</key>\n"
         "   <array>\n";

    for (; I != FirstNonNote; ++I)
      Printer.ReportDiag(o, **I);

    o << "   </array>\n";
  }

  o << "   <key>path</key>\n";

  o << "   <array>\n";

  for (const auto &Piece : llvm::make_range(I, Path.end()))
    Printer.ReportDiag(o, *Piece);

  o << "   </array>\n";

  Printer.ReportConstraintTrace(o, CFGs, Symbols, Graphs, /* indent */ 3);

  if (!DiagOpts.ShouldDisplayMacroExpansions)
    return;

  o << "   <key>macro_expansions</key>\n"
       "   <array>\n";
  Printer.ReportMacroExpansions(o, /* indent */ 4);
  o << "   </array>\n";
}

void PlistDiagnostics::FlushDiagnosticsImpl(
                                    std::vector<const PathDiagnostic *> &Diags,
                                    FilesMade *filesMade) {
  // Build up a set of FIDs that we use by scanning the locations and
  // ranges of the diagnostics.
  FIDMap FM;
  SmallVector<FileID, 10> Fids;
  const SourceManager& SM = PP.getSourceManager();
  const LangOptions &LangOpts = PP.getLangOpts();

  auto AddPieceFID = [&FM, &Fids, &SM](const PathDiagnosticPiece &Piece) {
    AddFID(FM, Fids, SM, Piece.getLocation().asLocation());
    ArrayRef<SourceRange> Ranges = Piece.getRanges();
    for (const SourceRange &Range : Ranges) {
      AddFID(FM, Fids, SM, Range.getBegin());
      AddFID(FM, Fids, SM, Range.getEnd());
    }
    // A call site of a frame the path is in can be in a file no piece is.
    if (const PathDiagnosticConstraintSnapshotRef &Snapshot =
            Piece.getConstraintSnapshot();
        Snapshot && Snapshot->Node) {
      if (Snapshot->Node->Location.isValid())
        AddFID(FM, Fids, SM, Snapshot->Node->Location);
      for (const auto &Frame : Snapshot->Node->Stack)
        if (Frame.CallSite.isValid())
          AddFID(FM, Fids, SM, Frame.CallSite);
    }
  };

  for (const PathDiagnostic *D : Diags) {

    SmallVector<const PathPieces *, 5> WorkList;
    WorkList.push_back(&D->path);

    while (!WorkList.empty()) {
      const PathPieces &Path = *WorkList.pop_back_val();

      for (const auto &Iter : Path) {
        const PathDiagnosticPiece &Piece = *Iter;
        AddPieceFID(Piece);

        if (const PathDiagnosticCallPiece *Call =
                dyn_cast<PathDiagnosticCallPiece>(&Piece)) {
          if (auto CallEnterWithin = Call->getCallEnterWithinCallerEvent())
            AddPieceFID(*CallEnterWithin);

          if (auto CallEnterEvent = Call->getCallEnterEvent())
            AddPieceFID(*CallEnterEvent);

          WorkList.push_back(&Call->path);
        } else if (const PathDiagnosticMacroPiece *Macro =
                       dyn_cast<PathDiagnosticMacroPiece>(&Piece)) {
          WorkList.push_back(&Macro->subPieces);
        }
      }
    }
  }

  // Open the file.
  std::error_code EC;
  llvm::raw_fd_ostream o(OutputFile, EC, llvm::sys::fs::OF_TextWithCRLF);
  if (EC) {
    llvm::errs() << "warning: could not create file: " << EC.message() << '\n';
    return;
  }

  EmitPlistHeader(o);

  // Write the root object: a <dict> containing...
  //  - "clang_version", the string representation of clang version
  //  - "files", an <array> mapping from FIDs to file names
  //  - "diagnostics", an <array> containing the path diagnostics
  //  - "constraint_trace_cfgs", the control flow graphs constraint traces
  //    name, when there are any
  o << "<dict>\n" <<
       " <key>clang_version</key>\n";
  EmitString(o, getClangFullVersion()) << '\n';
  o << " <key>diagnostics</key>\n"
       " <array>\n";

  CFGTable Graphs;

  for (std::vector<const PathDiagnostic*>::iterator DI=Diags.begin(),
       DE = Diags.end(); DI!=DE; ++DI) {

    o << "  <dict>\n";

    const PathDiagnostic *D = *DI;
    // The statement of a symbol is often in a file only the coverage below
    // names, such as a header with a callee the path left out. Adding the
    // coverage's files first, in its order, keeps every file the index it had
    // without the symbol table.
    if (!D->getSymbols().empty()) {
      for (const auto &[FID, Lines] : D->getExecutedLines())
        AddFID(FM, Fids, FID);
      for (const PathDiagnosticSymbol &Sym : D->getSymbols()) {
        if (!Sym.Conjured)
          continue;
        for (SourceLocation Loc : {Sym.Conjured->Location, Sym.Conjured->Loop})
          if (Loc.isValid())
            AddFID(FM, Fids, SM, Loc);
      }
    }
    printBugPath(o, FM, D->path, D->getCFGs(), D->getSymbols(), Graphs);

    // Output the bug type and bug category.
    o << "   <key>description</key>";
    EmitString(o, D->getShortDescription()) << '\n';
    o << "   <key>category</key>";
    EmitString(o, D->getCategory()) << '\n';
    o << "   <key>type</key>";
    EmitString(o, D->getBugType()) << '\n';
    o << "   <key>check_name</key>";
    EmitString(o, D->getCheckerName()) << '\n';

    o << "   <!-- This hash is experimental and going to change! -->\n";
    o << "   <key>issue_hash_content_of_line_in_context</key>";
    PathDiagnosticLocation UPDLoc = D->getUniqueingLoc();
    FullSourceLoc L(SM.getExpansionLoc(UPDLoc.isValid()
                                           ? UPDLoc.asLocation()
                                           : D->getLocation().asLocation()),
                    SM);

    EmitString(o, D->getIssueHash(SM, LangOpts)) << '\n';

    // Output information about the semantic context where
    // the issue occurred.
    if (const Decl *DeclWithIssue = D->getDeclWithIssue()) {
      // FIXME: handle blocks, which have no name.
      if (const NamedDecl *ND = dyn_cast<NamedDecl>(DeclWithIssue)) {
        StringRef declKind;
        switch (ND->getKind()) {
          case Decl::CXXRecord:
            declKind = "C++ class";
            break;
          case Decl::CXXMethod:
            declKind = "C++ method";
            break;
          case Decl::ObjCMethod:
            declKind = "Objective-C method";
            break;
          case Decl::Function:
            declKind = "function";
            break;
          default:
            break;
        }
        if (!declKind.empty()) {
          const std::string &declName = ND->getDeclName().getAsString();
          o << "  <key>issue_context_kind</key>";
          EmitString(o, declKind) << '\n';
          o << "  <key>issue_context</key>";
          EmitString(o, declName) << '\n';
        }

        // Output the bug hash for issue unique-ing. Currently, it's just an
        // offset from the beginning of the function.
        if (const Stmt *Body = DeclWithIssue->getBody()) {

          // If the bug uniqueing location exists, use it for the hash.
          // For example, this ensures that two leaks reported on the same line
          // will have different issue_hashes and that the hash will identify
          // the leak location even after code is added between the allocation
          // site and the end of scope (leak report location).
          if (UPDLoc.isValid()) {
            FullSourceLoc UFunL(
                SM.getExpansionLoc(
                    D->getUniqueingDecl()->getBody()->getBeginLoc()),
                SM);
            o << "  <key>issue_hash_function_offset</key><string>"
              << L.getExpansionLineNumber() - UFunL.getExpansionLineNumber()
              << "</string>\n";

          // Otherwise, use the location on which the bug is reported.
          } else {
            FullSourceLoc FunL(SM.getExpansionLoc(Body->getBeginLoc()), SM);
            o << "  <key>issue_hash_function_offset</key><string>"
              << L.getExpansionLineNumber() - FunL.getExpansionLineNumber()
              << "</string>\n";
          }

        }
      }
    }

    // Output the location of the bug.
    o << "  <key>location</key>\n";
    EmitLocation(o, SM, D->getLocation().asLocation(), FM, 2);

    // Output the diagnostic to the sub-diagnostic client, if any.
    if (!filesMade->empty()) {
      StringRef lastName;
      PDFileEntry::ConsumerFiles *files = filesMade->getFiles(*D);
      if (files) {
        for (PDFileEntry::ConsumerFiles::const_iterator CI = files->begin(),
                CE = files->end(); CI != CE; ++CI) {
          StringRef newName = CI->first;
          if (newName != lastName) {
            if (!lastName.empty()) {
              o << "  </array>\n";
            }
            lastName = newName;
            o <<  "  <key>" << lastName << "_files</key>\n";
            o << "  <array>\n";
          }
          o << "   <string>" << CI->second << "</string>\n";
        }
        o << "  </array>\n";
      }
    }

    printCoverage(D, /*IndentLevel=*/2, Fids, FM, o);

    // Close up the entry.
    o << "  </dict>\n";
  }

  o << " </array>\n";

  o << " <key>files</key>\n"
       " <array>\n";
  for (FileID FID : Fids)
    EmitString(o << "  ", SM.getFileEntryRefForID(FID)->getName()) << '\n';
  o << " </array>\n";

  Graphs.print(o);

  if (llvm::AreStatisticsEnabled() && DiagOpts.ShouldSerializeStats) {
    o << " <key>statistics</key>\n";
    std::string stats;
    llvm::raw_string_ostream os(stats);
    llvm::PrintStatisticsJSON(os);
    EmitString(o, html::EscapeText(stats)) << '\n';
  }

  // Finish.
  o << "</dict>\n</plist>\n";
}

//===----------------------------------------------------------------------===//
// Definitions of helper functions and methods for expanding macros.
//===----------------------------------------------------------------------===//

static std::optional<StringRef>
getExpandedMacro(SourceLocation MacroExpansionLoc,
                 const cross_tu::CrossTranslationUnitContext &CTU,
                 const MacroExpansionContext &MacroExpansions,
                 const SourceManager &SM) {
  if (auto CTUMacroExpCtx =
          CTU.getMacroExpansionContextForSourceLocation(MacroExpansionLoc)) {
    return CTUMacroExpCtx->getExpandedText(MacroExpansionLoc);
  }
  return MacroExpansions.getExpandedText(MacroExpansionLoc);
}
