#include <iostream>
#include <spot/tl/formula.hh>
#include <spot/tl/parse.hh>
#include <spot/tl/print.hh>
#include <spot/tl/ltlf.hh>
#include <spot/twa/twagraph.hh>
#include <spot/twaalgos/translate.hh>
#include <spot/twaalgos/remprop.hh>
#include <spot/twa/bddprint.hh>

void printAutomatonDetails(const std::string& name, spot::twa_graph_ptr aut) {
    std::cout << "\n=== " << name << " ===" << std::endl;
    std::cout << "States: " << aut->num_states() << std::endl;
    
    // Print accepting states
    std::cout << "Accepting states: [";
    bool first = true;
    for (unsigned s = 0; s < aut->num_states(); ++s) {
        if (aut->state_is_accepting(s)) {
            if (!first) std::cout << ", ";
            std::cout << s;
            first = false;
        }
    }
    std::cout << "]" << std::endl;
    
    // Print detailed transitions
    std::cout << "Detailed transitions:" << std::endl;
    auto dict = aut->get_dict();
    for (unsigned s = 0; s < aut->num_states(); ++s) {
        std::cout << "  State " << s << " (accepting: " << (aut->state_is_accepting(s) ? "yes" : "no") << "):" << std::endl;
        for (auto& t : aut->out(s)) {
            std::cout << "    -> " << t.dst << " if " << spot::bdd_format_formula(aut->get_dict(), t.cond) << std::endl;
        }
    }
}

int main() {
    std::cout << "=== DETAILED AUTOMATON ANALYSIS ===" << std::endl;
    
    // Original LTL formula
    std::string ltlFormula = "G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))";
    std::cout << "\nORIGINAL LTL FORMULA: " << ltlFormula << std::endl;
    
    spot::formula f = spot::parse_infix_psl(ltlFormula).f;
    
    // Approach 1: Monitor (Safety)
    spot::translator trans1;
    trans1.set_type(spot::postprocessor::Monitor);
    trans1.set_pref(spot::postprocessor::Deterministic);
    spot::twa_graph_ptr monitor = trans1.run(f);
    printAutomatonDetails("MONITOR (SAFETY)", monitor);
    
    // Approach 2: TGBA (Infinite)
    spot::translator trans2;
    trans2.set_type(spot::postprocessor::TGBA);
    trans2.set_pref(spot::postprocessor::Deterministic);
    spot::twa_graph_ptr tgba = trans2.run(f);
    printAutomatonDetails("TGBA (INFINITE)", tgba);
    
    // Approach 3: LTLf Finite Semantics
    spot::formula ltlfFormula = spot::from_ltlf(f);
    spot::translator trans3;
    trans3.set_type(spot::postprocessor::Buchi);
    trans3.set_pref(spot::postprocessor::Deterministic | spot::postprocessor::SBAcc);
    spot::twa_graph_ptr buchi = trans3.run(ltlfFormula);
    spot::twa_graph_ptr finite = spot::to_finite(buchi);
    printAutomatonDetails("LTLf FINITE SEMANTICS", finite);
    
    return 0;
}
