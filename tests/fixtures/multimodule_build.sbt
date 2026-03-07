name := "root-project"

lazy val common = (project in file("common"))
  .settings(
    libraryDependencies ++= Seq(
      "com.typesafe.play" %% "play-json" % "2.9.4",
      "org.slf4j" % "slf4j-api" % "1.7.36"
    )
  )

lazy val api = (project in file("api"))
  .dependsOn(common)
  .settings(
    libraryDependencies ++= Seq(
      "com.typesafe.play" %% "play" % "2.8.19",
      "com.typesafe.akka" %% "akka-http-core" % "10.1.15"
    )
  )

lazy val root = (project in file("."))
  .aggregate(common, api)
