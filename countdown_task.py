class CountdownTask:
    def __init__(self):
        self._running = True

    def terminate(self):
        self._running = False

    def run(self, action, n):
        action()
        # while self._running and n > 0:
        #     print('T-minus', n)
        #     n -= 1
        #     time.sleep(1)
