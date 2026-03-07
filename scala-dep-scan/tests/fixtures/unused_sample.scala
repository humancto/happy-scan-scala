package com.example.unused

// This file only imports play-json but doesn't import guava, commons-lang, etc.
import play.api.libs.json.Json

object UnusedExample {
  val x = Json.parse("{}")
}
