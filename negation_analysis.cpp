#include <iostream>
#include <spot/tl/formula.hh>
#include <spot/tl/parse.hh>
#include <spot/tl/print.hh>
#include <spot/tl/ltlf.hh>
#include <spot/twa/twagraph.hh>
#include <spot/twaalgos/translate.hh>
#include <spot/twaalgos/remprop.hh>

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
    
    // Print transitions
    std::cout << "Transitions:" << std::endl;
    for (unsigned s = 0; s < aut->num_states(); ++s) {
        std::cout << "  State " << s << " (accepting: " << (aut->state_is_accepting(s) ? "yes" : "no") << "):";
        for (auto& t : aut->out(s)) {
            std::cout << " -> " << t.dst;
        }
        std::cout << std::endl;
    }
}

int main() {
    std::cout << "=== NEGATION-BASED VIOLATION DETECTION ANALYSIS ===" << std::endl;
    
    // Original LTL formula
    std::string ltlFormula = "G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))";
    std::cout << "\nORIGINAL LTL FORMULA: " << ltlFormula << std::endl;
    
    spot::formula f = spot::parse_infix_psl(ltlFormula).f;
    
    // Negated formula
    spot::formula negated = spot::formula::Not(f);
    std::cout << "\nNEGATED LTL FORMULA: " << spot::str_psl(negated) << std::endl;
    
    // Approach 1: Monitor (Safety) on NEGATED formula
    spot::translator trans1;
    trans1.set_type(spot::postprocessor::Monitor);
    trans1.set_pref(spot::postprocessor::Deterministic);
    spot::twa_graph_ptr monitor_neg = trans1.run(negated);
    printAutomatonDetails("MONITOR (SAFETY) ON NEGATED", monitor_neg);
    
    // Approach 2: TGBA (Infinite) on NEGATED formula
    spot::translator trans2;
    trans2.set_type(spot::postprocessor::TGBA);
    trans2.set_pref(spot::postprocessor::Deterministic);
    spot::twa_graph_ptr tgba_neg = trans2.run(negated);
    printAutomatonDetails("TGBA (INFINITE) ON NEGATED", tgba_neg);
    
    // Approach 3: LTLf Finite Semantics on NEGATED formula
    spot::formula ltlfFormula_neg = spot::from_ltlf(negated);
    std::cout << "\nNEGATED LTLf FORMULA: " << spot::str_psl(ltlfFormula_neg) << std::endl;
    
    spot::translator trans3;
    trans3.set_type(spot::postprocessor::Buchi);
    trans3.set_pref(spot::postprocessor::Deterministic | spot::postprocessor::SBAcc);
    spot::twa_graph_ptr buchi_neg = trans3.run(ltlfFormula_neg);
    spot::twa_graph_ptr finite_neg = spot::to_finite(buchi_neg, "alive");
    printAutomatonDetails("LTLf FINITE SEMANTICS ON NEGATED", finite_neg);
    
    return 0;
}
