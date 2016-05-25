from multiprocessing import Pool
import time
import logging

logger = logging.getLogger("radula")


class ParallelSim(object):
    STOP = 'radula.parallel.STOP'

    def __init__(self, processes=2, label="Progress"):
        self.pool = Pool(processes=processes)
        self.total_processes = 0
        self.completed_processes = 0
        self.results = []
        self.timing = [0, 0]
        self.label = label

    def add(self, func, args):
        self.pool.apply_async(func=func, args=args, callback=self.complete)
        self.total_processes += 1

    def complete(self, result):
        if result == ParallelSim.STOP:
            self.terminate()
            return

        self.results.append(result)
        self.completed_processes += 1
        logger.info(
            '%s: %0.2f%%  %s/%s',
            self.label,
            100 * self.completed_processes / float(self.total_processes),
            self.completed_processes,
            self.total_processes,
        )
        self.timing[1] = time.time()

    def run(self):
        self.timing[0] = time.time()
        self.pool.close()
        self.pool.join()

    def get_results(self):
        return self.results

    def get_timing(self):
        return self.timing[1] - self.timing[0]

    def terminate(self):
        self.pool.terminate()

    def completed(self):
        return self.completed_processes == self.total_processes
