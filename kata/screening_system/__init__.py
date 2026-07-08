from kata.screening_system.models import ScreeningDecision, ScreeningFinding

__all__ = ["ScreeningDecision", "ScreeningFinding", "screen_submission"]


def screen_submission(*args, **kwargs):
    from kata.screening_system.engine import screen_submission as _screen_submission

    return _screen_submission(*args, **kwargs)
