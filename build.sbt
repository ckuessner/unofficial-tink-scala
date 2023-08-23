ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / scalaVersion := "3.3.0"

lazy val root = crossProject(JVMPlatform, JSPlatform).crossType(CrossType.Full).in(file("."))
  .settings(
    name := "tink-scala",
    projectDependencies ++= Seq(
      "org.scalatest" %%% "scalatest" % "3.2.15" % Test,
      "org.scalatest" %%% "scalatest-flatspec" % "3.2.15" % Test,
    ),
    Test / parallelExecution := false
  ).jvmSettings(
    libraryDependencies += "com.github.sbt" % "junit-interface" % "0.13.3" % Test,
    projectDependencies ++= junitDeps,
  ).dependsOn(subtle)

lazy val subtle = crossProject(JVMPlatform, JSPlatform).crossType(CrossType.Pure).in(file("./subtle"))
  .settings(
    name := "tink-scala-subtle",
  ).jsSettings(
    libraryDependencies += ("org.scala-js" %%% "scalajs-java-securerandom" % "1.0.0").cross(CrossVersion.for3Use2_13)
  )

val junitDeps = Seq(
  "junit" % "junit" % "4.13.2" % Test,
  "com.google.truth" % "truth" % "1.1.3" % Test,
  "com.google.code.gson" % "gson" % "2.10.1" % Test,
)