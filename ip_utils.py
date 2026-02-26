class BoundedCounter:
    def __init__(self, max_size=1000):
        self.max_size = max_size
        self.counts = {}
    
    def increment(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        if len(self.counts) > self.max_size:
            # Remove oldest entry
            oldest_key = next(iter(self.counts))
            del self.counts[oldest_key]
    
    def get_top(self, n=10):
        return sorted(self.counts.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get(self, key, default=0):
        return self.counts.get(key, default)

class BoundedSet:
    def __init__(self, max_size=1000):
        self.max_size = max_size
        self.items = set()
    
    def add(self, item):
        if len(self.items) >= self.max_size:
            # Remove oldest item
            self.items.pop()
        self.items.add(item)
    
    def __contains__(self, item):
        return item in self.items
    
    def __len__(self):
        return len(self.items)
