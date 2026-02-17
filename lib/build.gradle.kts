plugins {
    `java-library`
    `check-lib-versions`
}

java {
    sourceCompatibility = JavaVersion.VERSION_25
    targetCompatibility = JavaVersion.VERSION_25

    if (!JavaVersion.current().isCompatibleWith(targetCompatibility)) {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(targetCompatibility.majorVersion))
        }
    }
}

val sharedLibsignalClientDir = rootProject.file("../../shared/libsignal/java/client/build/libs")
val autodetectedSharedLibsignalClientPath = sharedLibsignalClientDir
    .takeIf { it.isDirectory }
    ?.listFiles()
    ?.map { it.name to it.absolutePath }
    ?.filter { (name, _) -> name.startsWith("libsignal-client-") && name.endsWith(".jar") }
    ?.maxByOrNull { (name, _) -> name }
    ?.second

val libsignalClientPath = project.findProperty("libsignal_client_path")?.toString()
    ?: autodetectedSharedLibsignalClientPath

dependencies {
    if (libsignalClientPath == null) {
        throw GradleException(
            "Missing local libsignal-client jar. Build it in ../../shared/libsignal/java/client/build/libs " +
                "or pass -Plibsignal_client_path=/absolute/path/to/libsignal-client-*.jar"
        )
    }
    implementation(libs.signalservice) {
        exclude(group = "org.signal", module = "libsignal-client")
    }
    implementation(files(libsignalClientPath))
    implementation(libs.jackson.databind)
    implementation(libs.bouncycastle)
    implementation(libs.slf4j.api)
    implementation(libs.sqlite)
    implementation(libs.hikari)

    testImplementation(libs.junit.jupiter)
    testImplementation(platform(libs.junit.jupiter.bom))
    testRuntimeOnly(libs.junit.launcher)
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

configurations {
    implementation {
        resolutionStrategy.failOnVersionConflict()
    }
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.jar {
    manifest {
        attributes("Automatic-Module-Name" to "org.asamk.signal.manager")
    }
}
