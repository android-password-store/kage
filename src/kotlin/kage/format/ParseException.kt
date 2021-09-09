package kage.format

public sealed class ParseException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : Exception(message, cause)

public class InvalidArbitraryStringException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

public class InvalidVersionException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

public class InvalidRecipientException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

public class InvalidFooterException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)
