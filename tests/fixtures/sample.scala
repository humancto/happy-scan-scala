package com.example.app

import play.api.libs.json.{Json, JsValue, Format}
import play.api.mvc.{Action, BaseController}
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.model.GetObjectRequest

object MyService extends BaseController {
  def getItem(id: String) = Action {
    val client: AmazonS3 = ???
    val request = new GetObjectRequest("bucket", id)
    val json = Json.parse("{}")
    Ok(json)
  }
}
