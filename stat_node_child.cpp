/*
 * stat_node_child.cpp
 *
 *  Created on: 2019.06.30
 *      Author: yan
 */

#include "types.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <map>

struct edge_info {
	u64 head_addr;			//addr of head bbl
	u64 tail_addr;			//addr of tail bbl
	u16 head_id;				//random id of head bbl
	u16 tail_id;				//random id of tail bbl
	u16 hash;						//hash of edge
	u16 num_call;				//num of call in edge.
	u16 num_mem;				//num of mem function in edge.
};

struct edge_neighbor {
	unsigned short hash;						//hash of edge
	unsigned short hash_neighbor;	//hash of neighbor edge
	unsigned short num_call;				//num of call in edge. Only count 1st layer call.
	unsigned short num_mem;				//num of *alloc and *free function in edge. Only count 1st layer call.
};


typedef std::multimap<u64, edge_info> mmap_head_edge;
typedef std::pair<u64, edge_info> pair_head_edge;

struct edge_neighbor *g_edge_info = NULL;
unsigned int g_edge_info_num = 0;
unsigned short g_edge_info_index[MAP_SIZE];

int comp_hash(const void *a, const void *b) {
	return (((struct edge_info*)a)->hash - ((struct edge_info*)b)->hash);
}

/* Get unix time in milliseconds */
static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Display usage hints. */
static void usage(char* argv0) {

  printf("\n%s -i ifile -o ofile\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input file\n"
       "  -o dir        - output file\n\n",

       argv0);

  exit(1);

}

int main(int argc, char **argv)
{
	int opt;
	char *in_file = NULL;
	char *out_file = NULL;
	struct stat statbuf;

  while ((opt = getopt(argc, argv, "+i:o:")) > 0){

    switch (opt) {

      case 'i': /* input file, node_relate_file */

        if (in_file) FATAL("Multiple -i options not supported");
        in_file = optarg;
      	if (stat(in_file, &statbuf))		PFATAL("Unable to stat '%s'", in_file);

        break;

      case 'o': /* output file, edge_relate_file */

        if (out_file) FATAL("Multiple -o options not supported");
        out_file = optarg;
        break;

      default:

        usage(argv[0]);

    }
  }

  if (!in_file || !out_file) usage(argv[0]);


	u64 time_start = get_cur_time();

	FILE* f = fopen(in_file, "r");
	if (!f) PFATAL("Unable to open '%s'", in_file);

	char line[128];
	mmap_head_edge mmhe;

	u32 num_ei = 0;
	struct edge_info *ei = (struct edge_info*)malloc(statbuf.st_size / 32 * sizeof(struct edge_info));

	while(fgets(line, sizeof(line), f)){

		if('n' == line[1]) // last line is "analyse time:  "
			break;

		sscanf(line, "%u %u %u %u %u %u %u", &(ei[num_ei].head_addr), &(ei[num_ei].tail_addr), &(ei[num_ei].head_id),
				&(ei[num_ei].tail_id), &(ei[num_ei].hash), &(ei[num_ei].num_call), &(ei[num_ei].num_mem));

		mmhe.insert(pair_head_edge(ei[num_ei].head_addr, ei[num_ei]));

		if( ++num_ei > statbuf.st_size / 32)  PFATAL("alloc memory too small");

	}

	fclose(f);

	qsort(ei, num_ei, sizeof(struct edge_info), comp_hash);

	f = fopen(out_file, "wb");
	edge_neighbor en;

	for (int i=0; i<num_ei; ++i){

    fprintf(stdout, "\r%d/%d time=%ds", i, num_ei, (get_cur_time() - time_start)/1000);
    fflush(stdout);

    // find all value. method 1
		auto it = mmhe.find(ei[i].head_addr);
		int count = mmhe.count(ei[i].head_addr);
		for (int j=0; j < count; ++j, ++it) {
			if (it->second.hash == ei[i].hash) continue;  // don't count self
			en.hash = ei[i].hash;
			en.hash_neighbor = it->second.hash;
			en.num_call = it->second.num_call;
			en.num_mem = it->second.num_mem;
			fwrite(&en, 1, sizeof(edge_neighbor), f);
		}

    // find all value. method 2
		auto p = mmhe.equal_range(ei[i].tail_addr);
		for (it = p.first; it != p.second; ++it) {
			if (it->second.hash == ei[i].hash) continue;  // don't count self
			en.hash = ei[i].hash;
			en.hash_neighbor = it->second.hash;
			en.num_call = it->second.num_call;
			en.num_mem = it->second.num_mem;
			fwrite(&en, 1, sizeof(edge_neighbor), f);
		}
	}

	fclose(f);
	free(ei);

  fprintf(stdout, "\n%d\n", get_cur_time() - time_start);

	return 0;
}
