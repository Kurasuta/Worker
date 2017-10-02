# Worker

Kurasuta worker. Is responsible for extraction of data from a PE file. Plugin architecture, all classes in extractor
directory derived from `BaseExtractor` will be executed and can get `pe` and `data` injected on creation. The process
method is then responsible to mutate an object of type `Sample` which in turn can be converted to JSON.
