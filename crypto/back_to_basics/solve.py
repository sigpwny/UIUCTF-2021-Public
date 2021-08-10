from main import *
from collections import deque, namedtuple

class SearchNode:
    def __init__(self, string, bases=[]):
         self.string = string
         self.bases = bases
    def __repr__(self):
        return f"{self.string[:10]}, {self.bases}"
def bfs(root):
    discovered = {root}
    queue = deque([root])
    while len(queue) > 0:
        print(f"length of queue: {len(queue)}")
        tmp = queue.popleft()
        print(f"looking at: {tmp}")
        current_string = tmp.string
        if current_string[:6] == b"uiuctf": return current_string
        try:
            max_base = max([ALPHABET.index(chr(i)) for i in set(current_string)]) + 1
            for base in range(max_base, 37):
                new_string = base_n_decode(current_string, base)
                neighbor = SearchNode(new_string, tmp.bases + [base])
                if neighbor not in discovered:
                    discovered.add(neighbor)
                    queue.append(neighbor)
        except:
            continue
    return "BFS failed"

root_node = SearchNode(open("public/flag_enc", "rb").read())
print(bfs(root_node))
