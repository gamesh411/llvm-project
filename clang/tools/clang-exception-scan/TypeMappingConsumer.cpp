#include "TypeMappingConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Type.h"
#include <llvm/Support/raw_ostream.h>
#include <unordered_map>
#include <unordered_set>

using namespace clang;
using namespace clang::exception_scan;

namespace {
class TypeMappingVisitor : public RecursiveASTVisitor<TypeMappingVisitor> {
public:
  TypeMappingVisitor(GlobalExceptionInfo &GCG, ASTContext &Context)
      : GCG_(GCG), Context_(Context) {}

  bool VisitCXXCatchStmt(CXXCatchStmt *CS) {
    if (!CS)
      return true;
    QualType QT = CS->getCaughtType();
    if (!QT.isNull()) {
      QualType NormQT = QT.getCanonicalType();
      while (NormQT->isReferenceType() || NormQT->isPointerType())
        NormQT = NormQT->getPointeeType();
      NormQT = NormQT.getUnqualifiedType();
      if (NormQT->isRecordType()) {
        std::string Canonical = NormQT.getAsString();
        CatchTypes_.insert(Canonical);
      }
    }
    return true;
  }

  bool VisitCXXRecordDecl(CXXRecordDecl *RD) {
    if (!RD->hasDefinition())
      return true;
    QualType QT =
        RD->getTypeForDecl() ? QualType(RD->getTypeForDecl(), 0) : QualType();
    if (QT.isNull())
      return true;
    QualType NormQT = QT.getCanonicalType();
    while (NormQT->isReferenceType() || NormQT->isPointerType())
      NormQT = NormQT->getPointeeType();
    NormQT = NormQT.getUnqualifiedType();
    if (!NormQT->isRecordType())
      return true;
    std::string ThisType = NormQT.getAsString();
    SeenTypes_.insert(ThisType);
    auto &Bases = InheritanceMap_[ThisType];
    for (const auto &Base : RD->bases()) {
      QualType BaseQT = Base.getType();
      if (!BaseQT.isNull()) {
        QualType NormBaseQT = BaseQT.getCanonicalType();
        while (NormBaseQT->isReferenceType() || NormBaseQT->isPointerType())
          NormBaseQT = NormBaseQT->getPointeeType();
        NormBaseQT = NormBaseQT.getUnqualifiedType();
        if (NormBaseQT->isRecordType()) {
          std::string BaseType = NormBaseQT.getAsString();
          Bases.insert(BaseType);
          SeenTypes_.insert(BaseType);
        }
      }
    }
    return true;
  }

  // After traversal, compute descendants for each catch type
  void buildDescendantMap() {
    // Build a map from type string to CXXRecordDecl*
    std::unordered_map<std::string, const CXXRecordDecl *> typeToDecl;
    for (auto &decl : Context_.getTranslationUnitDecl()->decls()) {
      if (auto *RD = llvm::dyn_cast<CXXRecordDecl>(decl)) {
        if (RD->hasDefinition()) {
          QualType QT = RD->getTypeForDecl() ? QualType(RD->getTypeForDecl(), 0)
                                             : QualType();
          if (!QT.isNull()) {
            QualType NormQT = QT.getCanonicalType();
            while (NormQT->isReferenceType() || NormQT->isPointerType())
              NormQT = NormQT->getPointeeType();
            NormQT = NormQT.getUnqualifiedType();
            if (NormQT->isRecordType()) {
              std::string ThisType = NormQT.getAsString();
              typeToDecl[ThisType] = RD;
            }
          }
        }
      }
    }

    // For each catch type, find all relevant descendants using full logic
    for (const std::string &catchType : CatchTypes_) {
      const CXXRecordDecl *BaseDecl = nullptr;
      auto baseIt = typeToDecl.find(catchType);
      if (baseIt != typeToDecl.end()) {
        BaseDecl = baseIt->second;
      }
      std::unordered_set<std::string> descendants;
      // Always include the base itself
      descendants.insert(catchType);
      // For each seen type, check if it is a valid descendant
      for (const auto &derivedType : SeenTypes_) {
        if (derivedType == catchType)
          continue;
        auto derivedIt = typeToDecl.find(derivedType);
        if (BaseDecl && derivedIt != typeToDecl.end()) {
          const CXXRecordDecl *DerivedDecl = derivedIt->second;
          CXXBasePaths Paths;
          if (DerivedDecl->isDerivedFrom(BaseDecl, Paths)) {
            // Check for ambiguous paths
            if (Paths.isAmbiguous(
                    CanQualType::CreateUnsafe(Context_.getCanonicalType(
                        Context_.getRecordType(DerivedDecl))))) {
              continue;
            }
            // Check for at least one all-public path
            bool AllPublic = false;
            for (const CXXBasePath &Path : Paths) {
              bool PathAllPublic = true;
              for (const CXXBasePathElement &Element : Path) {
                if (Element.Base->getAccessSpecifier() != AS_public) {
                  PathAllPublic = false;
                  break;
                }
              }
              if (PathAllPublic) {
                AllPublic = true;
                break;
              }
            }
            if (!AllPublic)
              continue;
            descendants.insert(derivedType);
          }
        }
      }
      // Store in global map
      std::lock_guard<std::mutex> Lock(GCG_.CatchTypeToDescendantsMutex);
      for (const std::string &desc : descendants) {
        GCG_.CatchTypeToDescendants[catchType].insert(desc);
      }
    }
  }

private:
  GlobalExceptionInfo &GCG_;
  ASTContext &Context_;
  std::unordered_set<std::string> CatchTypes_;
  std::unordered_set<std::string> SeenTypes_;
  std::unordered_map<std::string, std::unordered_set<std::string>>
      InheritanceMap_;
};
} // namespace

void TypeMappingConsumer::HandleTranslationUnit(ASTContext &Context) {
  TypeMappingVisitor Visitor(GCG_, Context);
  Visitor.TraverseDecl(Context.getTranslationUnitDecl());
  Visitor.buildDescendantMap();
}

std::unique_ptr<FrontendAction> TypeMappingActionFactory::create() {
  return std::make_unique<TypeMappingAction>(GCG_);
}