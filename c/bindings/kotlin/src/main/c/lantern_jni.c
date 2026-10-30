/*
 * The JNI side of the Kotlin sketch (../kotlin/dev/boreale/lantern/Lantern.kt):
 * each native method is one or two calls of the C API. The app's Transport
 * (a Kotlin object) becomes a lantern_transport whose send() calls it back
 * on the same thread.
 */
#include <jni.h>

#include <stdlib.h>
#include <string.h>

#include <lantern/lantern.h>

/* The native methods of dev.boreale.lantern.Native, as javac -h would declare them */
JNIEXPORT jint JNICALL Java_dev_boreale_lantern_Native_version(JNIEnv* env, jobject self);
JNIEXPORT jstring JNICALL Java_dev_boreale_lantern_Native_shortForm(
    JNIEnv* env, jobject self, jbyteArray sha256);
JNIEXPORT jlong JNICALL Java_dev_boreale_lantern_Native_clientCreate(
    JNIEnv* env, jobject self, jstring origin, jstring user_agent, jstring platform, jobject transport);
JNIEXPORT jobjectArray JNICALL Java_dev_boreale_lantern_Native_clientHandshake(
    JNIEnv* env, jobject self, jlong handle);
JNIEXPORT void JNICALL Java_dev_boreale_lantern_Native_clientFree(JNIEnv* env, jobject self, jlong handle);

/* A client and what it holds. */
typedef struct native_client
{
    JavaVM* vm;
    jobject transport; /* a global reference */
    lantern_transport* lantern_transport;
    lantern_random* random;
    lantern_client* client;
} native_client;

static void throw_error(JNIEnv* env, const lantern_error* error)
{
    jclass type = (*env)->FindClass(env, "dev/boreale/lantern/LanternException");
    if (type == NULL)
        return;
    jmethodID make = (*env)->GetMethodID(env, type, "<init>", "(IILjava/lang/String;Ljava/lang/String;)V");
    jstring code   = (*env)->NewStringUTF(env, error->code_text);
    jstring detail = (*env)->NewStringUTF(
        env, error->detail[0] != '\0' ? error->detail : lantern_status_name(error->status));
    jobject thrown
        = (*env)->NewObject(env, type, make, (jint)error->status, (jint)error->http_status, code, detail);
    if (thrown != NULL)
        (*env)->Throw(env, (jthrowable)thrown);
}

static jstring new_string(JNIEnv* env, lantern_str text)
{
    /* NewStringUTF takes modified UTF-8: fine for the protocol's texts, which hold no NUL */
    return (*env)->NewStringUTF(env, text.data);
}

/* lantern_transport_callbacks.send: the Kotlin Transport, called back. */
static lantern_status transport_send(
    void* user, const lantern_request* request, lantern_response* response, lantern_error* error)
{
    native_client* native = user;
    JNIEnv* env           = NULL;
    if ((*native->vm)->GetEnv(native->vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK)
    {
        lantern_error_set(error, LANTERN_ERROR_TRANSPORT, "not on a thread the JVM knows");
        return LANTERN_ERROR_TRANSPORT;
    }
    jclass string_type   = (*env)->FindClass(env, "java/lang/String");
    jobjectArray headers = (*env)->NewObjectArray(env, (jsize)(request->header_count * 2), string_type, NULL);
    for (size_t i = 0; i < request->header_count; ++i)
    {
        (*env)->SetObjectArrayElement(
            env, headers, (jsize)(2 * i), new_string(env, request->headers[i].name));
        (*env)->SetObjectArrayElement(
            env, headers, (jsize)(2 * i + 1), new_string(env, request->headers[i].value));
    }
    jbyteArray body = (*env)->NewByteArray(env, (jsize)request->body_size);
    if (request->body_size > 0)
        (*env)->SetByteArrayRegion(env, body, 0, (jsize)request->body_size, (const jbyte*)request->body);
    jclass transport_type = (*env)->GetObjectClass(env, native->transport);
    jmethodID method      = (*env)->GetMethodID(env, transport_type, "send",
             "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;[B)Ldev/boreale/lantern/HttpResponse;");
    jobject answer        = (*env)->CallObjectMethod(env, native->transport, method,
               new_string(env, request->method_name), new_string(env, request->url), headers, body);
    if ((*env)->ExceptionCheck(env) || answer == NULL)
    {
        (*env)->ExceptionClear(env);
        lantern_error_set(error, LANTERN_ERROR_TRANSPORT, "the app's transport threw");
        return LANTERN_ERROR_TRANSPORT;
    }
    jclass answer_type = (*env)->GetObjectClass(env, answer);
    const jint status
        = (*env)->CallIntMethod(env, answer, (*env)->GetMethodID(env, answer_type, "getStatus", "()I"));
    jobjectArray lines = (jobjectArray)(*env)->CallObjectMethod(
        env, answer, (*env)->GetMethodID(env, answer_type, "getHeaders", "()[Ljava/lang/String;"));
    jbyteArray bytes = (jbyteArray)(*env)->CallObjectMethod(
        env, answer, (*env)->GetMethodID(env, answer_type, "getBody", "()[B"));
    if (!lantern_response_status(response, (uint16_t)status))
        return LANTERN_OK;
    const jsize count = lines == NULL ? 0 : (*env)->GetArrayLength(env, lines);
    for (jsize i = 0; i + 1 < count; i += 2)
    {
        jstring name     = (jstring)(*env)->GetObjectArrayElement(env, lines, i);
        jstring value    = (jstring)(*env)->GetObjectArrayElement(env, lines, i + 1);
        const char* n    = (*env)->GetStringUTFChars(env, name, NULL);
        const char* v    = (*env)->GetStringUTFChars(env, value, NULL);
        const bool go_on = lantern_response_header(response, n, strlen(n), v, strlen(v));
        (*env)->ReleaseStringUTFChars(env, name, n);
        (*env)->ReleaseStringUTFChars(env, value, v);
        if (!go_on)
            return LANTERN_OK;
    }
    if (bytes != NULL)
    {
        jbyte* data      = (*env)->GetByteArrayElements(env, bytes, NULL);
        const jsize size = (*env)->GetArrayLength(env, bytes);
        lantern_response_body(response, (const uint8_t*)data, (size_t)size);
        (*env)->ReleaseByteArrayElements(env, bytes, data, JNI_ABORT);
    }
    return LANTERN_OK;
}

static void free_native(JNIEnv* env, native_client* native)
{
    lantern_client_free(native->client);
    lantern_transport_free(native->lantern_transport);
    lantern_random_free(native->random);
    if (native->transport != NULL)
        (*env)->DeleteGlobalRef(env, native->transport);
    free(native);
}

JNIEXPORT jint JNICALL Java_dev_boreale_lantern_Native_version(JNIEnv* env, jobject self)
{
    (void)env;
    (void)self;
    return (jint)lantern_version();
}

JNIEXPORT jstring JNICALL Java_dev_boreale_lantern_Native_shortForm(
    JNIEnv* env, jobject self, jbyteArray sha256)
{
    (void)self;
    uint8_t digest[32];
    if ((*env)->GetArrayLength(env, sha256) != 32)
        return NULL;
    (*env)->GetByteArrayRegion(env, sha256, 0, 32, (jbyte*)digest);
    char out[20];
    lantern_short_form(digest, out);
    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jlong JNICALL Java_dev_boreale_lantern_Native_clientCreate(
    JNIEnv* env, jobject self, jstring origin, jstring user_agent, jstring platform, jobject transport)
{
    (void)self;
    lantern_error error   = LANTERN_INIT(lantern_error);
    native_client* native = calloc(1, sizeof(native_client));
    if (native == NULL)
        return 0;
    (*env)->GetJavaVM(env, &native->vm);
    native->transport                     = (*env)->NewGlobalRef(env, transport);
    lantern_transport_callbacks callbacks = LANTERN_INIT(lantern_transport_callbacks);
    callbacks.user                        = native;
    callbacks.send                        = transport_send;
    lantern_status status = lantern_transport_create(&callbacks, NULL, &native->lantern_transport, &error);
    if (status == LANTERN_OK)
        status = lantern_random_create_system(NULL, &native->random, &error);
    if (status == LANTERN_OK)
    {
        const char* o = (*env)->GetStringUTFChars(env, origin, NULL);
        const char* u = (*env)->GetStringUTFChars(env, user_agent, NULL);
        const char* p = platform == NULL ? NULL : (*env)->GetStringUTFChars(env, platform, NULL);
        lantern_client_config config = LANTERN_INIT(lantern_client_config);
        config.origin                = o;
        config.user_agent            = u;
        config.platform              = p;
        config.transport             = native->lantern_transport;
        config.random                = native->random;
        /* The client copies the strings */
        status = lantern_client_create(&config, &native->client, &error);
        (*env)->ReleaseStringUTFChars(env, origin, o);
        (*env)->ReleaseStringUTFChars(env, user_agent, u);
        if (p != NULL)
            (*env)->ReleaseStringUTFChars(env, platform, p);
    }
    if (status != LANTERN_OK)
    {
        free_native(env, native);
        throw_error(env, &error);
        return 0;
    }
    return (jlong)(intptr_t)native;
}

JNIEXPORT jobjectArray JNICALL Java_dev_boreale_lantern_Native_clientHandshake(
    JNIEnv* env, jobject self, jlong handle)
{
    (void)self;
    native_client* native       = (native_client*)(intptr_t)handle;
    lantern_error error         = LANTERN_INIT(lantern_error);
    lantern_handshake* shake    = NULL;
    const lantern_status status = lantern_client_handshake(native->client, &shake, &error);
    if (status == LANTERN_ABSENT)
        return NULL;
    if (status != LANTERN_OK)
    {
        throw_error(env, &error);
        return NULL;
    }
    jobjectArray out = (*env)->NewObjectArray(env, 3, (*env)->FindClass(env, "java/lang/String"), NULL);
    (*env)->SetObjectArrayElement(env, out, 0, new_string(env, lantern_handshake_get_uid(shake)));
    (*env)->SetObjectArrayElement(env, out, 1, new_string(env, lantern_handshake_get_name(shake)));
    (*env)->SetObjectArrayElement(env, out, 2, new_string(env, lantern_handshake_get_base(shake)));
    lantern_handshake_free(shake);
    return out;
}

JNIEXPORT void JNICALL Java_dev_boreale_lantern_Native_clientFree(JNIEnv* env, jobject self, jlong handle)
{
    (void)self;
    if (handle != 0)
        free_native(env, (native_client*)(intptr_t)handle);
}
