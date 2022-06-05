#include "PartitionSort.h"
// #include <time.h>

// void get_monotonic_time(struct timespec* ts) {
//     clock_gettime(CLOCK_MONOTONIC, ts);
// }

// long get_time_nano(struct timespec* ts) {
//     return (long)ts->tv_sec * 1e9 + ts->tv_nsec;
// }

// double get_elapsed_time_sec(struct timespec* before, struct timespec* after) {
//     double deltat_s  = after->tv_sec - before->tv_sec;
//     double deltat_ns = after->tv_nsec - before->tv_nsec;
//     return deltat_s + deltat_ns*1e-9;
// }

// long get_elapsed_time_nano(struct timespec* before, struct timespec* after) {
//     return get_time_nano(after) - get_time_nano(before);
// }

// struct timespec s;
// struct timespec e;

void PartitionSort::InsertRule(const Rule& one_rule) {

	// get_monotonic_time(&s);
	for (auto mitree : mitrees)
	{
		bool prioritychange = false;
		
		bool success = mitree->TryInsertion(one_rule, prioritychange);
		if (success) {
			
			if (prioritychange) {
				InsertionSortMITrees();
			}
			mitree->ReconstructIfNumRulesLessThanOrEqualTo(10);
			rules.push_back(std::make_pair(one_rule, mitree));
			return;
		}
	}
	bool priority_change = false;
	 
	auto tree_ptr = new OptimizedMITree(one_rule);
	tree_ptr->TryInsertion(one_rule, priority_change);
	rules.push_back(std::make_pair(one_rule, tree_ptr));
	mitrees.push_back(tree_ptr);  
	InsertionSortMITrees();
	// get_monotonic_time(&e);
	// printf("%lu\n", get_elapsed_time_nano(&s, &e));
}


void PartitionSort::DeleteRule(size_t i){
	if (i < 0 || i >= rules.size()) {
		printf("Warning index delete rule out of bound: do nothing here\n");
		printf("%lu vs. size: %lu", i, rules.size());
		return;
	}
	bool prioritychange = false;

	OptimizedMITree * mitree = rules[i].second; 
	mitree->Deletion(rules[i].first, prioritychange); 
 
	if (prioritychange) {
		InsertionSortMITrees();
	}


	if (mitree->Empty()) {
		mitrees.pop_back();
		delete mitree;
	}


	if (i != rules.size() - 1) {
		rules[i] = std::move(rules[rules.size() - 1]);
	}
	rules.pop_back();


}
