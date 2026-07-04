from scripts.benchmark_search import percentile


def test_percentile_interpolates_sorted_values():
    assert percentile([10.0, 20.0, 30.0], 0.5) == 20.0
    assert percentile([10.0, 20.0, 30.0], 0.95) == 29.0


def test_percentile_handles_empty_and_single_value():
    assert percentile([], 0.95) == 0.0
    assert percentile([42.0], 0.95) == 42.0
