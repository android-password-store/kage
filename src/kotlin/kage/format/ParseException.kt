package kage.format

public class ParseException : Exception {
  public constructor() : super()
  public constructor(message: String) : super(message)
  public constructor(message: String, cause: Throwable) : super(message, cause)
}
