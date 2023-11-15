<?php

declare(strict_types=1);

namespace Equit\Totp;

use DateInterval;
use Equit\Totp\Exceptions\InvalidTimeStepException;

final class TotpTimeStep
{
    private int $seconds;

    /**
     * @throws InvalidTimeStepException
     */
    public function __construct(int $seconds)
    {
        if (1 > $seconds) {
            throw new InvalidTimeStepException($seconds, "The time step for a TOTP must be >= 1 second.");
        }

        $this->seconds = $seconds;
    }

    /** @return int The length of the time step, in seconds. */
    public function seconds(): int
    {
        return $this->seconds;
    }

    /**
     * @throws InvalidTimeStepException
     */
    public function fromSeconds(int $seconds): self
    {
        return new self($seconds);
    }

    /**
     * @throws InvalidTimeStepException
     */
    public function fromMinutes(int $minutes): self
    {
        return new self($minutes * 60);
    }

    public function fromDateInterval(DateInterval $interval): self
    {
        if (0 !== $interval->y || 0 !== $interval->m) {
            throw new InvalidTimeStepException(0, "DateIntervals that include years or months cannot be used as they don't represent a fixed time interval.");
        }

        return new self(
            ($interval->d * 24 * 60 * 60)
            + ($interval->h * 60 * 60)
            + ($interval->m * 60)
            + $interval->s);
    }
}