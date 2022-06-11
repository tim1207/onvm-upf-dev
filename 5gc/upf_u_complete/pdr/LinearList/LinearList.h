#ifndef  LL_H
#define  LL_H

#include "../Simulation.h"

class LinearList : public PacketClassifier {
public:
	LinearList(){}
	void ConstructClassifier(const std::vector<Rule>& r) {
		rules = r;
		rules.reserve(100000);
		this->rules.reserve(rules.size());
		for (const auto& r : rules) {
			InsertRule(r);
		}
	}

	Memory MemSizeBytes() const {
		return 0;
	}

 
	int MemoryAccess() const {
		return 0;
	}
	size_t NumTables() const {
		return 0;
	}
	size_t RulesInTable(size_t tableIndex) const{
		return 0;
	}


	int ClassifyAPacket(const Packet& one_packet) {
		
		int result = -1;
		auto IsPacketMatchToRule = [](const Packet& p, const Rule& r) {
			for (int i = 0; i < r.dim; i++) {
				if (p[i] < r.range[i][0]) {
					// printf("p[%d]: %u", i, p[i]);
					// printf("r.range[%d][0]: ", i);
					// std::cout << r.range[i][0] << std::endl;
					return 0;
				}
				if (p[i] > r.range[i][1]) {
					// printf("p[%d]: %u", i, p[i]);
					// printf("r.range[%d][0]: ", i);
					// std::cout << r.range[i][0] << std::endl;
					return 0;
				}
			}
			return 1;
		};
		
		for (size_t j = 0; j < rules.size(); j++) {
			// std::cout << "11111" << std::endl;
			if (IsPacketMatchToRule(one_packet, rules[j])) {
				result = std::max(rules[j].priority, result);
			}
		}
		// std::cout << "LISDhsiladjioasjdoip" << std::endl;
		return result;
	}

	void DeleteRule(size_t i) {
		if (i < 0 || i >= rules.size()) {
			printf("Warning index delete rule out of bound: do nothing here\n");
			printf("%d vs. size: %d", i, rules.size());
			return;
		}
		if (i != rules.size() -1)
		rules[i]=std::move(rules[rules.size() - 1]);
		rules.pop_back();
	}
	void InsertRule(const Rule& one_rule) { 
		rules.push_back(one_rule);
	}
	int Size() const {
		return 0;
	}
	std::vector<Rule> GetRules() const {
		return rules;
	}
private:
	std::vector<Rule> rules;

};

#endif
