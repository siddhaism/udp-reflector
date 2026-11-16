"""Statistics shared by the UDP client and reflector server."""

import math


def percentile(data, percent):
    """Return an interpolated percentile, or None when there are no samples."""
    if not data:
        return None
    if percent <= 0:
        return float(min(data))
    if percent >= 100:
        return float(max(data))

    # A percentile can fall between two samples. Interpolate between their
    # values so small datasets still give a useful result.
    sorted_samples = sorted(data)
    position = (len(sorted_samples) - 1) * (percent / 100.0)
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    if lower_index == upper_index:
        return float(sorted_samples[lower_index])
    lower_weight = upper_index - position
    upper_weight = position - lower_index
    return float(
        sorted_samples[lower_index] * lower_weight
        + sorted_samples[upper_index] * upper_weight
    )


def stddev(samples):
    """Return population standard deviation, or None for an empty sequence."""
    if not samples:
        return None

    # Compute the average once, then measure how far samples spread around it.
    # Dividing by the full sample count preserves the reports' population formula.
    average = sum(samples) / len(samples)
    variance = sum((sample - average) ** 2 for sample in samples) / len(samples)
    return variance ** 0.5


def smoothed_packet_rates(arrival_times_ms):
    """Count packets in each trailing second of an ordered timestamp sequence."""
    rates = []
    window_start_index = 0

    # Move the left edge forward as arrivals leave the one-second window.
    # Include both endpoints, matching the client and server's existing reports.
    for arrival_index, arrival_ms in enumerate(arrival_times_ms):
        window_start_ms = arrival_ms - 1000.0
        while (
            window_start_index < arrival_index
            and arrival_times_ms[window_start_index] < window_start_ms
        ):
            window_start_index += 1
        packet_count = arrival_index - window_start_index + 1
        rates.append(float(packet_count))
    return rates
