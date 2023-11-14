<?php

namespace Equit\Totp\Contracts;

/**
 * Interface for classes that convert bidirectionally  between raw data and a specific encoding.
 *
 * The general concept is that at any point in time, an instance of the class represents some known piece of data, and
 * can be queried for both the raw and encoded forms of that data. The data it currently represents can be set in either
 * form. Once set, the previous data the object represented is entirely forgotten, and the raw and encoded data qeeried
 * from the object represent the new data, regardless of whether it was set in encoded or raw form.
 */
interface Codec
{
    /**
     * Set the raw form of the data.
     *
     * @param string $raw The data.
     *
     * Subsequent calls to raw() will return this data. Subsequent calls to encoded() will return the encoded form of
     * this data.
     */
    public function setRaw(string $raw): void;

    /**
     * Set the encoded form of the data.
     *
     * @param string $encoded The encoded data.
     *
     * Subsequent calls to raw() will return the raw (decoded) form of this data. Subsequent calls to encoded() will
     * return this data.
     */
    public function setEncoded(string $encoded): void;

    /**
     * Fetch the currently represented data, in raw form.
     *
     * @return string The data.
     */
    public function raw(): string;

    /**
     * Fetch the currently represented data, in encoded form.
     *
     * @return string The data.
     */
    public function encoded(): string;
}
