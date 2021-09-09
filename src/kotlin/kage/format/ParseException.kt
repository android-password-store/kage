package kage.format

public sealed class ParseException(message: String? = null, cause: Throwable? = null) :
  Exception(message, cause)

public class InvalidArbitraryStringException : ParseException {
  public constructor() : super()
  public constructor(message: String) : super(message)
  public constructor(message: String, cause: Throwable) : super(message, cause)
}

public class InvalidVersionException : ParseException {
  public constructor() : super()
  public constructor(message: String) : super(message)
  public constructor(message: String, cause: Throwable) : super(message, cause)
}

public class InvalidRecipientException : ParseException {
  public constructor() : super()
  public constructor(message: String) : super(message)
  public constructor(message: String, cause: Throwable) : super(message, cause)
}

public class IncompleteRecipientException : ParseException {
  public constructor() : super()
  public constructor(message: String) : super(message)
  public constructor(message: String, cause: Throwable) : super(message, cause)
}

public class InvalidFooterException : ParseException {
  public constructor() : super()
  public constructor(message: String) : super(message)
  public constructor(message: String, cause: Throwable) : super(message, cause)
}
