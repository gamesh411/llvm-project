#include <iostream>
#include <spot/tl/formula.hh>
#include <spot/tl/parse.hh>
#include <spot/tl/print.hh>
#include <spot/tl/ltlf.hh>
#include <spot/twa/twagraph.hh>
#include <spot/twaalgos/translate.hh>
#include <spot/twaalgos/remprop.hh>

int main() {
    std::cout << "=== AUTOMATON GENERATION ANALYSIS ===" << std::endl;
    
    // Original LTL formula
    std::string ltlFormula = "G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))";
    std::cout << "\n1. ORIGINAL LTL FORMULA:" << std::endl;
    std::cout << "   " << ltlFormula << std::endl;
    
    spot::formula f = spot::parse_infix_psl(ltlFormula).f;
    
    // Approach 1: Monitor (Safety)
    std::cout << "\n2. MONITOR (SAFETY) APPROACH:" << std::endl;
    spot::translator trans1;
    trans1.set_type(spot::postprocessor::Monitor);
    trans1.set_pref(spot::postprocessor::Deterministic);
    spot::twa_graph_ptr monitor = trans1.run(f);
    
    std::cout << "   States: " << monitor->num_states() << std::endl;
    std::cout << "   Accepting states: [";
    bool first = true;
    for (unsigned s = 0; s < monitor->num_states(); ++s) {
        if (monitor->state_is_accepting(s)) {
            if (!first) std::cout << ", ";
            std::cout << s;
            first = false;
        }
    }
    std::cout << "]" << std::endl;
    
    // Print transitions
    std::cout << "   Transitions:" << std::endl;
    for (unsigned s = 0; s < monitor->num_states(); ++s) {
        std::cout << "     State " << s << ":";
        for (auto& t : monitor->out(s)) {
            std::cout << " -> " << t.dst;
        }
        std::cout << std::endl;
    }
    
    // Approach 2: TGBA (Infinite)
    std::cout << "\n3. TGBA (INFINITE) APPROACH:" << std::endl;
    spot::translator trans2;
    trans2.set_type(spot::postprocessor::TGBA);
    trans2.set_pref(spot::postprocessor::Deterministic);
    spot::twa_graph_ptr tgba = trans2.run(f);
    
    std::cout << "   States: " << tgba->num_states() << std::endl;
    std::cout << "   Accepting states: [";
    first = true;
    for (unsigned s = 0; s < tgba->num_states(); ++s) {
        if (tgba->state_is_accepting(s)) {
            if (!first) std::cout << ", ";
            std::cout << s;
            first = false;
        }
    }
    std::cout << "]" << std::endl;
    
    // Print transitions
    std::cout << "   Transitions:" << std::endl;
    for (unsigned s = 0; s < tgba->num_states(); ++s) {
        std::cout << "     State " << s << ":";
        for (auto& t : tgba->out(s)) {
            std::cout << " -> " << t.dst;
        }
        std::cout << std::endl;
    }
    
    // Approach 3: LTLf Finite Semantics
    std::cout << "\n4. LTLf FINITE SEMANTICS APPROACH:" << std::endl;
    spot::formula ltlfFormula = spot::from_ltlf(f);
    std::cout << "   LTLf formula: " << spot::str_psl(ltlfFormula) << std::endl;
    
    spot::translator trans3;
    trans3.set_type(spot::postprocessor::Buchi);
    trans3.set_pref(spot::postprocessor::Deterministic | spot::postprocessor::SBAcc);
    spot::twa_graph_ptr buchi = trans3.run(ltlfFormula);
    spot::twa_graph_ptr finite = spot::to_finite(buchi);
    
    std::cout << "   Büchi states: " << buchi->num_states() << std::endl;
    std::cout << "   Finite states: " << finite->num_states() << std::endl;
    std::cout << "   Accepting states: [";
    first = true;
    for (unsigned s = 0; s < finite->num_states(); ++s) {
        if (finite->state_is_accepting(s)) {
            if (!first) std::cout << ", ";
            std::cout << s;
            first = false;
        }
    }
    std::cout << "]" << std::endl;
    
    // Print transitions
    std::cout << "   Transitions:" << std::endl;
    for (unsigned s = 0; s < finite->num_states(); ++s) {
        std::cout << "     State " << s << ":";
        for (auto& t : finite->out(s)) {
            std::cout << " -> " << t.dst;
        }
        std::cout << std::endl;
    }
    
    return 0;
}
