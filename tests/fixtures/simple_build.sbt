name := "test-project"

version := "1.0.0"

scalaVersion := "2.13.10"

val akkaVersion = "2.6.19"

libraryDependencies ++= Seq(
  "com.typesafe.play" %% "play-json" % "2.3.2",
  "com.typesafe.play" %% "play-ws" % "2.3.2",
  "mysql" % "mysql-connector-java" % "5.1.31",
  "com.amazonaws" % "aws-java-sdk-s3" % "1.12.100",
  "ch.qos.logback" % "logback-classic" % "1.0.9",
  "commons-lang" % "commons-lang" % "2.6",
  "org.specs2" %% "specs2-core" % "2.3.12" % "test",
  "com.typesafe.akka" %% "akka-actor" % akkaVersion,
  "org.cvogt" %% "play-json-extensions" % "0.2",
  "com.google.guava" % "guava" % "28.0-jre"
)
