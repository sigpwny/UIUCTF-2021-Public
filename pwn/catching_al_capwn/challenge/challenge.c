#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
/**
*   cskel was developed for chal.dev by Thomas Quig (quig.dev)
*   
*   Created early 2020, edited for clarity and uploaded 4/22/21
*   compiel with `gcc -std=c99 -o challenge challenge.c -g -O0 -fno-stack-protector -m32 -g -Wno-deprecated-declarations -z execstack`
**/
#define START_NODE 0x00
#define END_NODE 0xff
#define NAME_SIZE 0x18
#define INPUT_SIZE 0x10
#define NUM_NODES 256
#define u_char unsigned char
typedef struct _graph {
    char name[16];
    u_char node_values[NUM_NODES];
    u_char adjmatrix[NUM_NODES][NUM_NODES];
} graph;

void init_graph(graph * g){
    for(int i = 0; i < NUM_NODES; i++)
    {
        for(int j = 0; j < NUM_NODES; j++)
        {
            g->adjmatrix[i][j] = 0x00;
        }
    }
}

void set_edge(graph * g,u_char src,u_char dst, u_char weight)
{
    if(g == NULL)
        exit(0x00F);
    else
        g->adjmatrix[(int)src][(int)dst] = weight;
}

void add_edge(graph * g, u_char src, u_char dst, u_char weight)
{
    if(g == NULL || g->adjmatrix[(int)src][(int)dst] != 0x00)
        exit(0x00F);
    else
        set_edge(g,src,dst,weight);
}

void remove_edge(graph * g, u_char src, u_char dst)
{
    if(g == NULL || g->adjmatrix[(int)src][(int)dst] == 0x00)
        exit(0x00F);
    else
        set_edge(g,src,dst,0);
}

void set_node_value(graph * g, int n, char v){
    if(g == NULL)
        exit(0x00F);
    else
        g->node_values[(int)n] = v;
}

int minDistance(int dist[], bool sptSet[])
{
    int min = INT_MAX, min_index;
 
    for (int v = 0; v < NUM_NODES; v++)
        if (sptSet[v] == false && dist[v] <= min)
            min = dist[v], min_index = v;
 
    return min_index;
}

// Gets the shortest path, returns the node values Completely stolen from geeksforgeeks ty
int shortest_path(graph * g, int src, int dst, char * ret){
    // The output array. dist[i]
    // will hold the shortest
    // distance from src to i
    int dist[NUM_NODES]; 
   
    // sptSet[i] will true if vertex
    // i is included / in shortest
    // path tree or shortest distance 
    // from src to i is finalized
    bool sptSet[NUM_NODES];
   
    // Parent array to store
    // shortest path tree
    int parent[NUM_NODES];
   
    // Initialize all distances as 
    // INFINITE and stpSet[] as false
    for (int i = 0; i < NUM_NODES; i++)
    {
        parent[0] = -1;
        dist[i] = INT_MAX;
        sptSet[i] = false;
    }
   
    // Distance of source vertex 
    // from itself is always 0
    dist[src] = 0;
   
    // Find shortest path
    // for all vertices
    for (int count = 0; count < NUM_NODES - 1; count++)
    {
        // Pick the minimum distance
        // vertex from the set of
        // vertices not yet processed. 
        // u is always equal to src
        // in first iteration.
        int u = minDistance(dist, sptSet);
   
        // Mark the picked vertex 
        // as processed
        sptSet[u] = true;
   
        // Update dist value of the 
        // adjacent vertices of the
        // picked vertex.
        for (int v = 0; v < NUM_NODES; v++)
   
            // Update dist[v] only if is
            // not in sptSet, there is
            // an edge from u to v, and 
            // total weight of path from
            // src to v through u is smaller
            // than current value of
            // dist[v]
            if (!sptSet[v] && g->adjmatrix[u][v] &&
                dist[u] + g->adjmatrix[u][v] < dist[v])
            {
                parent[v] = u;
                dist[v] = dist[u] + g->adjmatrix[u][v];
            } 
    }
   
    // print the constructed
    // distance array
    // printPath(parent,(int)dst);
    char spath[256]; memset(spath,0,256);
    int pos = (int)dst;
    while(pos != -1){
        //printf("spath[%i] = %02hhx\n", pos, g->node_values[(int)pos]);
        spath[pos] = g->node_values[(int)pos];
        pos = parent[pos];
    }
    int idx = 0;
    for(int i = 0;  i < 256; i++)
    {
        if(spath[i]){
            ret[idx] = spath[i];
            idx++;
        }
    }
    //printSolution(dist, NUM_NODES, parent);
}

void catch_al()
{
    void * name_addr;
    unsigned char input_buf[16] = "";
    unsigned char short_path[NUM_NODES] = "";

    graph g;
    init_graph(&g);
    name_addr = &g.name;

    // print the adjacency list representation of the above graph
    // print_graph(&g);
    int i = 64;
    while(i > 0){
        printf("%i Commands Remaining: ",i);
        fgets(input_buf,INPUT_SIZE,stdin); input_buf[INPUT_SIZE - 1] == 0;
        switch(input_buf[0]){
            case 'N': // NAME Graph, you done after this so hit it with that bof
                i = 0;
                break;
            case 'E': // Add Edge
                add_edge(&g,input_buf[1],input_buf[2],input_buf[3]);
                break;
            case 'R': // Remove Edge
                remove_edge(&g,input_buf[1],input_buf[2]);
                break;
            case 'V': // Set node value
                //printf("%c %02hhx %02hhx | ",input_buf[0],input_buf[1],input_buf[2]);
                set_node_value(&g,input_buf[1],input_buf[2]);
                break;
            default:
                exit(0x00F);
        }
        i--;
    }
    
    printf("Brilliant sir! We just need a bit more information!\n");
    printf("Where did Capwn start and end [S][E]: ");
    unsigned char start, end;

    fgets(input_buf,INPUT_SIZE,stdin);
    start = input_buf[0];
    end= input_buf[1];
    
    printf("This creation will surely help us catch Al Capwn!\nWe filed the result in filing cabinet <%p>\n",short_path);
    printf("What is your creation's name: ");
    
    fgets(input_buf,NAME_SIZE,stdin);
    memcpy(name_addr,input_buf,NAME_SIZE);
    shortest_path(&g,start,end,short_path);
   
    printf("\nLets go get that criminal!\n");
}

void print_welcome()
{
    printf("Welcome detective, help us find where Al Capwn went and is going to go!\n");
}

int main()
{
    // These functions set the buffers and makes sure flushing works properly. Ignore them
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    
    print_welcome();
    
    catch_al();
}