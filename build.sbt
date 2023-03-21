ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.2.2"

lazy val root = (project in file("."))
  .settings(
    name := "pure-scala-tink",
    libraryDependencies += "com.github.sbt" % "junit-interface" % "0.13.3" % Test,
    projectDependencies ++= Seq(
      "junit" % "junit" % "4.13.2" % Test,
      "com.google.truth" % "truth" % "0.44" % Test,
      "com.google.code.gson" % "gson" % "2.10.1" % Test
    )
  )
