"""Recognition policy, independent of the neural-network runtime."""
import math
import time


def normalize(vector):
    if len(vector) != 128 or not all(math.isfinite(float(x)) for x in vector):
        raise ValueError("Invalid face feature")
    norm = math.sqrt(sum(float(x) ** 2 for x in vector))
    if norm < 1e-8:
        raise ValueError("Empty face feature")
    return [float(x) / norm for x in vector]


def similarity(a, b):
    return sum(x * y for x, y in zip(a, b))


def identify(feature, candidates, threshold=0.50, margin=0.06):
    scores = []
    for person_id, samples in candidates.items():
        values = sorted((similarity(feature, s) for s in samples), reverse=True)
        if values:
            scores.append((sum(values[:2]) / min(2, len(values)), person_id))
    scores.sort(reverse=True)
    if not scores:
        return None, 0.0
    best, person_id = scores[0]
    if best < threshold or (len(scores) > 1 and best - scores[1][0] < margin):
        return None, best
    return person_id, best


class StabilityGate:
    """Require separated, consecutive observations from one camera session.

    This reduces transient matches. It is NOT a liveness or anti-spoof test.
    """
    def __init__(self, required=3, clock=time.monotonic):
        self.required, self.clock, self.states = required, clock, {}

    def reset(self, key):
        self.states.pop(key, None)

    def observe(self, key, person_id):
        now = self.clock()
        self.states = {k: v for k, v in self.states.items() if now - v[2] < 15}
        if person_id is None:
            self.reset(key)
            return 0, False
        previous = self.states.get(key)
        if not previous or previous[0] != person_id or now - previous[2] > 2.5:
            count = 1
        elif now - previous[2] < 0.20:
            return previous[1], False
        else:
            count = min(self.required, previous[1] + 1)
        self.states[key] = (person_id, count, now)
        return count, count >= self.required
