#pragma once

#include <iostream>
#include <string>
#include <regex>
#include <curl/curl.h>
#include <vector>
#include <chrono>
#include <iomanip>
#include <map>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <thread>
#include <algorithm>
#include <mutex>
#include <cmath>
#include <atomic>
#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <queue>
#include <condition_variable>
#include <future>
#include <cctype>
using namespace std;

mutex mtx;
std::queue<std::string> linkQueue;
std::mutex queueMutex;
std::mutex linkMutex;
std::mutex fileMutex;
std::condition_variable cv;
bool stopCrawling = false;
std::atomic<bool> workDone(false);
std::atomic<int> requestsMade(0);
std::mutex rateLimitMutex;
std::condition_variable rateLimitCv;
std::chrono::steady_clock::time_point lastRequestTime = std::chrono::steady_clock::now();

namespace target {
    string protocol;
    string host;
    string port;
    string startingPath;
    string targetUrl;
    int timeoutCount = 0;
    std::unordered_set<std::string> links;
    std::unordered_set<std::string> checkedLinks;
    bool sitemapFound = false;
}

namespace config {
    string ua = "default";
    bool debug = false;
    string default_ua = "kekpath/v1.0";
    long defaultTimeout = 5000;
    int maxrps = 50;
    int numThreads = 4;
    string outputpath;
    string network_interface = "NaN";
    std::vector<std::string> excludedExtensions;
}

struct WebRequestResult {
    bool status;
    string targetHost;
    vector<string> requestHeaders;
    int statusCode;
    string responseBody;
    vector<string> responseHeaders;
    string redirectUrl;
    double responseTimeMs;
    bool timedout;
};

string getStatusDescription(int statusCode) {
    map<int, string> statusDescriptions = {
        // 1xx: Informational
        {100, "Continue"},
        {101, "Switching Protocols"},
        {102, "Processing"}, // WebDAV

        // 2xx: Success
        {200, "OK"},
        {201, "Created"},
        {202, "Accepted"},
        {203, "Non-Authoritative Information"},
        {204, "No Content"},
        {205, "Reset Content"},
        {206, "Partial Content"},
        {207, "Multi-Status"}, // WebDAV
        {208, "Already Reported"}, // WebDAV
        {226, "IM Used"}, // HTTP Delta encoding

        // 3xx: Redirection
        {300, "Multiple Choices"},
        {301, "Moved Permanently"},
        {302, "Found"},
        {303, "See Other"},
        {304, "Not Modified"},
        {305, "Use Proxy"},
        {306, "(Unused)"},
        {307, "Temporary Redirect"},
        {308, "Permanent Redirect"},

        // 4xx: Client Errors
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {402, "Payment Required"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {405, "Method Not Allowed"},
        {406, "Not Acceptable"},
        {407, "Proxy Authentication Required"},
        {408, "Request Timeout"},
        {409, "Conflict"},
        {410, "Gone"},
        {411, "Length Required"},
        {412, "Precondition Failed"},
        {413, "Payload Too Large"},
        {414, "URI Too Long"},
        {415, "Unsupported Media Type"},
        {416, "Range Not Satisfiable"},
        {417, "Expectation Failed"},
        {418, "I'm a teapot"}, // April Fools' joke, defined in RFC 2324
        {421, "Misdirected Request"},
        {422, "Unprocessable Entity"}, // WebDAV
        {423, "Locked"}, // WebDAV
        {424, "Failed Dependency"}, // WebDAV
        {425, "Too Early"},
        {426, "Upgrade Required"},
        {428, "Precondition Required"},
        {429, "Too Many Requests"},
        {431, "Request Header Fields Too Large"},
        {451, "Unavailable For Legal Reasons"},

        // 5xx: Server Errors
        {500, "Internal Server Error"},
        {501, "Not Implemented"},
        {502, "Bad Gateway"},
        {503, "Service Unavailable"},
        {504, "Gateway Timeout"},
        {505, "HTTP Version Not Supported"},
        {506, "Variant Also Negotiates"},
        {507, "Insufficient Storage"}, // WebDAV
        {508, "Loop Detected"}, // WebDAV
        {510, "Not Extended"},
        {511, "Network Authentication Required"}
    };

    auto it = statusDescriptions.find(statusCode);
    return (it != statusDescriptions.end()) ? it->second : "Unknown Status";
}

std::string getUa() {
    std::vector<std::string> userAgents = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/18.18362",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/114.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A5341f Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A5341f Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 13_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 OPR/78.0.4093.147",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/44.18362.449.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 9; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/114.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:114.0) Gecko/20100101 Firefox/114.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; AS; rv:11.0) like Gecko",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; AS; rv:11.0) like Gecko"
    };

    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    int index = std::rand() % userAgents.size();

    return userAgents[index];
}

void addLink(const std::string& link) {
    auto linkExists = [](const std::string& link) {
        return target::links.find(link) != target::links.end() ||
            target::checkedLinks.find(link) != target::checkedLinks.end();
    };

    if (!linkExists(link)) {
        target::links.insert(link);
    }
}

void dbg(const string& msg) {
    if (!config::debug) return;
    const string debugPrefix = "[debug] ";
    cout << debugPrefix << msg << endl;
}

void setOutputPath() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm* local_time = std::localtime(&now_time);

    std::string currentPath = std::filesystem::current_path().string();

    std::ostringstream oss;
    oss << "/kekpath-"
        << std::put_time(local_time, "%H-%M-%S")
        << ".txt";

    config::outputpath = currentPath + oss.str();
    dbg("Output path set to: " + config::outputpath);
}

void printRequestDump(const WebRequestResult& result) {
    dbg("Printing request dump...");

    const string whiteBoldText = "\033[1;97m";
    const string resetText = "\033[0m";

    const string padding = "  ";

    int width = max(60, static_cast<int>(result.targetHost.length() + padding.length() + 10));

    string borderTop(width, '_');
    string borderBottom(width, '-');

    cout << borderTop << endl;

    cout << padding << whiteBoldText << "Host: " << resetText << result.targetHost << endl;

    cout << padding << whiteBoldText << "Time: " << resetText << result.responseTimeMs << " ms." << endl;

    cout << padding << whiteBoldText << "Status-Code: " << resetText
        << result.statusCode << " - " << getStatusDescription(result.statusCode) << endl;

    if (result.statusCode >= 300 && result.statusCode < 400) {
        string redirectUrl = result.redirectUrl.empty() ? "NaN" : result.redirectUrl;
        cout << padding << whiteBoldText << "Redirect-URL: " << resetText << redirectUrl << endl;
    }

    cout << padding << whiteBoldText << "Response Body Size: " << resetText
        << result.responseBody.size() << " bytes" << endl;

    vector<string> commonHeaders = { "Content-Type", "Server", "Location", "Connection", "Cache-Control", "Set-Cookie", "Content-Length", "Access-Control-Allow-Origin", "X-Frame-Options", "X-XSS-Protection", "Referrer-Policy", "X-Powered-By", "Keep-Alive" };
    int commonHeadersCount = 0;
    int totalHeaders = result.responseHeaders.size();

    dbg("Checking for common headers...");
    for (const auto& header : result.responseHeaders) {
        bool isCommonHeader = false;
        for (const auto& commonHeader : commonHeaders) {
            if (header.find(commonHeader) != string::npos) {
                cout << padding << whiteBoldText << commonHeader << ": " << resetText << header.substr(header.find(":") + 2);
                isCommonHeader = true;
                commonHeadersCount++;
                break;
            }
        }
    }

    int additionalHeaders = totalHeaders - commonHeadersCount;
    if (additionalHeaders > 0) {
        cout << padding << whiteBoldText << "+ " << additionalHeaders << " more headers" << resetText << endl;
    }

    cout << borderBottom << endl;

    dbg("Request dump complete.");
}

string say(const string& msg, const string& status = "") {
    const string redText = "\033[1;31m";
    const string blueText = "\033[1;94m";
    const string orangeText = "\033[1;33m";
    const string whiteText = "\033[1;97m";
    const string greenText = "\033[1;32m";
    const string yellowText = "\033[1;33m";
    const string resetText = "\033[0m";
    string kekpathPrefix = blueText + "kekpath" + resetText;

    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm* local_time = std::localtime(&now_time);

    if (status == "err" || status == "error" || status == "Error") {
        kekpathPrefix = redText + "kekpath" + resetText;
    }
    else if (status == "get" || status == "inp" || status == "input") {
        kekpathPrefix = orangeText + "kekpath" + resetText;
    }
    else if (status == "link") {
        int checkedCount = target::checkedLinks.size();
        int totalCount = target::links.size();
        cout << std::put_time(local_time, "%H:%M:%S")
            << " "
            << whiteText << "[" << resetText
            << greenText << std::to_string(checkedCount) << resetText
            << whiteText << "/" << resetText
            << yellowText << std::to_string(totalCount) << resetText
            << whiteText << "]" << resetText
            << " " << msg << std::endl;
        return "";
    }

    cout << std::put_time(local_time, "%H:%M:%S") << " "
        << whiteText << "[" << resetText
        << kekpathPrefix
        << whiteText << "]" << resetText
        << " " << msg;

    if (status == "get" || status == "inp" || status == "input") {
        cout << " ";
        string userInput;
        getline(cin, userInput);
        return userInput;
    }
    else {
        cout << std::endl;
    }

    return "";
}

void asyncFileWrite(const std::string& link, const std::string& status_code) {
    std::ofstream outFile;
    outFile.open(config::outputpath, std::ios::app);
    if (outFile.is_open()) {
        outFile << status_code << ";" << link << std::endl;
        outFile.close();
        say(status_code + " " + link, "link");
    }
    else {
        dbg("Failed to open output file: " + config::outputpath);
    }
}

void checkLink(const std::string& link, const std::string& status_code) {
    {
        std::lock_guard<std::mutex> lock(linkMutex);

        if (target::links.erase(link) > 0) {
            target::checkedLinks.insert(link);
        }
    }

    int sc = std::stoi(status_code);

    if ((sc >= 200 && sc < 300) || (sc >= 500) || (sc >= 401 && sc <= 403) || (sc == 302)) {
        auto future = std::async(std::launch::async, asyncFileWrite, link, status_code);
    }
}

bool isValidUrl(const string& url) {
    const regex url_regex(R"((http|https)://([\w.-]+)(:[0-9]+)?(/.*)?)");
    return regex_match(url, url_regex);
}

bool isValidPort(const string& port) {
    const regex port_regex("^\\d+$");
    if (regex_match(port, port_regex)) {
        int port_num = stoi(port);
        return port_num > 0 && port_num <= 65535;
    }
    return false;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t totalSize = size * nmemb;
    try {
        s->append((char*)contents, totalSize);
    }
    catch (const std::exception& e) {
        dbg("Exception in WriteCallback: " + std::string(e.what()));
    }
    return totalSize;
}

size_t HeaderCallback(char* buffer, size_t size, size_t nitems, std::vector<std::string>* headers) {
    size_t totalSize = size * nitems;
    headers->emplace_back(buffer, totalSize);
    return totalSize;
}

bool caseInsensitiveFind(const std::string& header, const std::string& key) {
    std::string lower_header = header;
    std::string lower_key = key;
    std::transform(lower_header.begin(), lower_header.end(), lower_header.begin(), ::tolower);
    std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
    return lower_header.find(lower_key) == 0;
}

WebRequestResult performWebRequest(const string& fullUrl, long timeoutMs = 5000, bool redirectCheck = true) {
    CURL* curl;
    CURLcode res;
    WebRequestResult result;
    long responseCode;
    double totalTime = 0.0;

    result.targetHost = fullUrl;
    result.status = false;
    result.timedout = false;
    dbg("Initializing CURL...");
    curl = curl_easy_init();
    if (!curl) {
        dbg("Failed to initialize CURL.");
        say("Failed to initialize CURL.", "err");
        return result;
    }

    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);

    string user_agent = config::default_ua;

    if (config::ua == "rand") {
        user_agent = getUa();
        dbg("Using random User-Agent: " + user_agent);
    }
    else if (config::ua != "default") {
        user_agent = config::ua;
        dbg("Using custom User-Agent: " + user_agent);
    }
    else {
        dbg("Using default User-Agent: " + user_agent);
    }

    dbg("Setting headers...");

    struct curl_slist* headers = nullptr;
    string userAgent = "User-Agent: " + user_agent;
    headers = curl_slist_append(headers, userAgent.c_str());
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (config::network_interface != "NaN") {
        curl_easy_setopt(curl, CURLOPT_INTERFACE, config::network_interface);
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.responseBody);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result.responseHeaders);

    dbg("Performing web request...");
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        if (res == CURLE_OPERATION_TIMEDOUT) {
            dbg("CURL request timed out: " + string(curl_easy_strerror(res)));
            result.timedout = true;
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return result;
    }
    else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &totalTime);

        result.statusCode = static_cast<int>(responseCode);
        result.responseTimeMs = totalTime * 1000;

        dbg("Received response with status code: " + to_string(result.statusCode));
        dbg("Response time: " + to_string(result.responseTimeMs) + " ms");

        result.redirectUrl = "NaN";
        if (result.statusCode >= 300 && result.statusCode < 400 && redirectCheck) {
            for (const auto& header : result.responseHeaders) {
                dbg("Header: " + header);
                if (caseInsensitiveFind(header, "location:")) {
                    string location = header.substr(10);
                    location.erase(0, location.find_first_not_of(" \t\r\n"));
                    location.erase(location.find_last_not_of(" \t\r\n") + 1);

                    if (location.find("http://") == 0 || location.find("https://") == 0) {
                        dbg("Processing absolute redirect URL: " + location);
                        string protocol = location.substr(0, location.find("://") + 3);

                        string host_and_port = location.substr(location.find("://") + 3);

                        size_t path_start = host_and_port.find('/');
                        string host_and_port_only = (path_start != string::npos) ? host_and_port.substr(0, path_start) : host_and_port;
                        string path = (path_start != string::npos) ? host_and_port.substr(path_start) : "/";

                        size_t port_pos = host_and_port_only.find(':');
                        if (port_pos != string::npos) {
                            target::port = host_and_port_only.substr(port_pos + 1);
                            host_and_port_only = host_and_port_only.substr(0, port_pos);
                            dbg("Extracted port from redirect URL: " + target::port);
                        }
                        else {
                            if (protocol == "http://") {
                                target::port = "80";
                            }
                            else if (protocol == "https://") {
                                target::port = "443";
                            }
                            dbg("Using default port: " + target::port);
                        }

                        result.redirectUrl = protocol + host_and_port_only + path;
                    }
                    else if (location.front() == '/') {
                        dbg("Processing relative redirect URL: " + location);
                        size_t scheme_end = fullUrl.find("://") + 3;
                        size_t path_start = fullUrl.find('/', scheme_end);

                        string baseUrl;
                        if (path_start != string::npos) {
                            baseUrl = fullUrl.substr(0, path_start);
                        }
                        else {
                            baseUrl = fullUrl;
                            if (baseUrl.back() == '/') {
                                baseUrl.pop_back();
                            }
                        }

                        result.redirectUrl = baseUrl + location;
                    }
                    dbg("Final redirect URL: " + result.redirectUrl);
                    break;
                }
            }
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    result.status = true;
    return result;
}

std::future<WebRequestResult> asyncWebRequest(const string& fullUrl, long timeoutMs = 5000, bool redirectCheck = true) {
    return std::async(std::launch::async, performWebRequest, fullUrl, timeoutMs, redirectCheck);
}

void parseUrl(const string& url, string& protocol, string& host, string& path) {
    const regex url_regex(R"(^(http|https)://([\w\.-]+)(:\d+)?(/.*)?$)");
    smatch url_match_result;
    if (regex_match(url, url_match_result, url_regex)) {
        protocol = url_match_result[1];
        host = url_match_result[2];
        if (url_match_result[4].matched) {
            path = url_match_result[4];
        }
        else {
            path = "/";
        }
    }
}

std::atomic<int> requestCount(0);

void requestWorker(const string& url, std::atomic<long>& totalResponseTime, std::atomic<long>& longestResponseTime, bool& stopFlag, int threadId, std::vector<int>& requestsPerThread) {
    while (!stopFlag) {
        auto requestStartTime = std::chrono::steady_clock::now();

        auto futureResult = asyncWebRequest(url, config::defaultTimeout);
        WebRequestResult result = futureResult.get();

        if (!result.status) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        auto requestEndTime = std::chrono::steady_clock::now();
        long responseTimeMs = result.responseTimeMs;

        requestCount.fetch_add(1, std::memory_order_relaxed);
        requestsPerThread[threadId]++;

        totalResponseTime.fetch_add(responseTimeMs, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lock(mtx);
            longestResponseTime.store(std::max(longestResponseTime.load(std::memory_order_relaxed), responseTimeMs), std::memory_order_relaxed);
        }

        if (result.statusCode < 200 || result.statusCode >= 300) {
            stopFlag = true;
            std::cout << std::endl;
            say("Worker " + std::to_string(threadId) + ": " + std::to_string(result.statusCode) + ", potential ratelimit detected.", "err");
        }

        auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(requestEndTime - requestStartTime).count();

        int sleepTime = (1000 * config::numThreads / config::maxrps) - elapsedTime;
        if (sleepTime > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
        }
    }
}

void displayProgressBar(int progress, int totalRequests, const std::vector<int>& requestsPerThread) {
    const int barWidth = 60;
    std::string progressBar;

    std::cout << "\r\033[K";
    std::cout << "\033[F\033[K";

    progressBar += "[";

    int pos = barWidth * progress / 100;

    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) progressBar += "=";
        else if (i == pos) progressBar += ">";
        else progressBar += " ";
    }

    progressBar += "] " + std::to_string(progress) + "% | Requests: " + std::to_string(totalRequests);

    std::cout << "\r" << progressBar << std::flush;

    std::cout << "\n";

    if (requestsPerThread.size() <= 6) {
        for (size_t i = 0; i < requestsPerThread.size(); ++i) {
            std::cout << " Thread " << i << ": " << requestsPerThread[i];
            if (i != requestsPerThread.size() - 1) {
                std::cout << " |";
            }
        }
    }

    std::cout << std::flush;
}
bool probeTarget(const string& url) {
    const int testDurationSeconds = 5;
    const int numThreads = config::numThreads;
    std::atomic<long> totalResponseTime(0);
    std::atomic<long> longestResponseTime(0);
    bool stopFlag = false;
    bool clean = false;
    std::vector<int> requestsPerThread(numThreads, 0);

    say("Initializing target connectivity probing...");
    auto startTime = std::chrono::steady_clock::now();
    std::vector<std::thread> threads;

    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(requestWorker, url, std::ref(totalResponseTime), std::ref(longestResponseTime), std::ref(stopFlag), i, std::ref(requestsPerThread));
    }

    std::cout << "\n\n" << std::flush;

    while (!stopFlag) {
        auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count();
        int progress = static_cast<int>((elapsedTime * 100) / (testDurationSeconds * 1000));
        displayProgressBar(progress, requestCount.load(std::memory_order_relaxed), requestsPerThread);

        if (elapsedTime > testDurationSeconds * 1000) {
            std::cout << std::endl;
            std::cout << std::endl;
            say("Probing finished with " + std::to_string(config::numThreads) + " workers.");
            stopFlag = true;
            clean = true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    if (requestCount.load() > 0) {
        long averageResponseTime = requestCount.load() > 0 ? totalResponseTime.load() / requestCount.load() : 0;
        say("Performed " + std::to_string(requestCount.load()) + " requests.");
        say("Average response time: " + std::to_string(averageResponseTime) + " ms.");
        say("Longest response time: " + std::to_string(longestResponseTime.load()) + " ms.");
        int rl = requestCount.load() / 5;
        int round_rl = (rl / 5) * 5;
        say("Probed rate:  " + std::to_string(rl) + " requests / second");
        if (round_rl < config::maxrps) {
            config::maxrps = round_rl;
        }
        if (longestResponseTime.load() < 9900 && longestResponseTime.load() >= 650) {
            config::defaultTimeout = longestResponseTime.load() + 100;
            dbg("Setting default timeout to " + std::to_string(config::defaultTimeout) + " ms.");
        }

        if (longestResponseTime.load() < 650) config::defaultTimeout = 750;
    }

    if (config::maxrps >= 5) {
        if (!clean) config::maxrps = config::maxrps / 5;
    }
    if (config::maxrps == 0) {
        config::maxrps = 1;
    }
    if (config::maxrps > 50) config::maxrps = 50;

    say("Setting timeout => " + std::to_string(config::defaultTimeout) + " ms.");
    say("Setting max. ratelimit => " + std::to_string(config::maxrps) + " / s");
    if (config::maxrps >= 20) {
        say("Rate is quite high, use -rl to set a fixed amount. (enter to continue)", "get");
    }

    return clean;
}
bool validResponse(WebRequestResult result) {
    if (result.status && result.statusCode >= 200 && result.statusCode < 300) {
        return true;
    }
    else {
        return false;
    }
}
std::string decodeUnicodeEscapes(const std::string& url) {
    std::string decodedUrl;
    std::regex unicodeRegex(R"(\\u([0-9a-fA-F]{4}))");
    std::smatch match;
    std::string::const_iterator searchStart(url.cbegin());

    while (std::regex_search(searchStart, url.cend(), match, unicodeRegex)) {
        decodedUrl.append(searchStart, match.prefix().second);
        int charCode = std::stoi(match[1].str(), nullptr, 16);
        decodedUrl += static_cast<char>(charCode);
        searchStart = match.suffix().first;
    }

    decodedUrl.append(searchStart, url.cend());
    return decodedUrl;
}

std::string sanitizeUrl(const std::string& url) {
    std::string cleanUrl = decodeUnicodeEscapes(url);

    size_t splitPos = cleanUrl.find(" o ");
    if (splitPos != std::string::npos) {
        cleanUrl = cleanUrl.substr(0, splitPos);
    }

    size_t angleBracketPos = cleanUrl.find("\">");
    if (angleBracketPos != std::string::npos) {
        cleanUrl = cleanUrl.substr(0, angleBracketPos);
    }

    size_t fragmentPos = cleanUrl.find('#');
    cleanUrl = (fragmentPos != std::string::npos) ? cleanUrl.substr(0, fragmentPos) : cleanUrl;

    size_t jsVerPos = cleanUrl.find("js?ver=");
    if (jsVerPos != std::string::npos) {
        cleanUrl = cleanUrl.substr(0, cleanUrl.find('?'));
    }
    else {
        size_t queryPos = cleanUrl.find('?');
        size_t illegalCharPos = std::string::npos;

        const std::string illegalChars = "{}|\\^[]*$()<>;'\"&>";

        for (size_t i = 0; i < cleanUrl.size(); ++i) {
            if (queryPos != std::string::npos && i >= queryPos) {
                break;
            }
            if (illegalChars.find(cleanUrl[i]) != std::string::npos) {
                illegalCharPos = i;
                break;
            }
        }

        if (illegalCharPos != std::string::npos) {
            cleanUrl = cleanUrl.substr(0, illegalCharPos);
        }

        if (queryPos != std::string::npos) {
            size_t ampersandPos = cleanUrl.find('&', queryPos);
            if (ampersandPos != std::string::npos) {
                cleanUrl = cleanUrl.substr(0, ampersandPos);
            }
        }
    }

    const std::string trailingIllegalChars = " \"";
    size_t endPos = cleanUrl.find_last_not_of(trailingIllegalChars);
    if (endPos != std::string::npos) {
        cleanUrl = cleanUrl.substr(0, endPos + 1);
    }

    if (!cleanUrl.empty() && (cleanUrl.back() == '?' || cleanUrl.back() == '$' || cleanUrl.back() == '\'')) {
        cleanUrl.pop_back();
    }

    return cleanUrl;
}

bool isHostAllowed(const std::string& url) {
    std::regex hostRegex(R"(^(http|https)://([\w\.-]+))");
    std::smatch match;

    if (std::regex_search(url, match, hostRegex)) {
        std::string host = match[2];
        return host == target::host || host.find("." + target::host) != std::string::npos;
    }

    return false;
}

void parseRobotsTxt(const std::string& robotsTxtContent) {
    std::istringstream stream(robotsTxtContent);
    std::string line;

    while (std::getline(stream, line)) {
        line = line.substr(0, line.find('#'));
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

        if (line.find("Sitemap:") == 0) {
            std::string sitemapUrl = line.substr(8);
            sitemapUrl = sanitizeUrl(sitemapUrl);

            if (!isValidUrl(sitemapUrl)) {
                sitemapUrl = target::targetUrl + sanitizeUrl(sitemapUrl);
            }

            if (isHostAllowed(sitemapUrl)) {
                target::sitemapFound = true;
                addLink(sitemapUrl);
            }
        }
        else if (line.find("Allow:") == 0 || line.find("Disallow:") == 0) {
            std::string path = line.substr(line.find(':') + 1);
            path = sanitizeUrl(path);

            if (!path.empty()) {
                std::string fullUrl;
                if (isValidUrl(path)) {
                    fullUrl = path;
                }
                else {
                    fullUrl = target::targetUrl + path;
                }

                if (isHostAllowed(fullUrl)) {
                    addLink(fullUrl);
                }
            }
        }
    }
}

void calcAttackVector() {
    say("Preparing enumeration, scanning for robots.txt & sitemap.");
    addLink(target::targetUrl + "/");
    addLink(target::targetUrl + target::startingPath);
    WebRequestResult robots_result = performWebRequest(target::targetUrl + "/robots.txt", config::defaultTimeout);
    if (validResponse(robots_result)) {
        say("Found robots.txt, parsing...");
        parseRobotsTxt(robots_result.responseBody);
        checkLink(target::targetUrl + "/robots.txt", to_string(robots_result.statusCode));
    }

    if (!target::sitemapFound) {
        std::vector<std::string> sitemapCandidates = {
            target::targetUrl + "/sitemap.xml",
            target::targetUrl + "/sitemap_index.xml",
            target::targetUrl + "/sitemap-index.xml",
            target::targetUrl + "/sitemap.php",
            target::targetUrl + "/sitemap.json",
            target::targetUrl + "/sitemap"
        };

        for (const auto& sitemapUrl : sitemapCandidates) {
            WebRequestResult sitemapResult = performWebRequest(sitemapUrl, config::defaultTimeout);
            if (validResponse(sitemapResult)) {
                target::sitemapFound = true;
                addLink(sitemapUrl);
                break;
            }
        }
    }
    if (target::sitemapFound) say("Found sitemap...");
}

std::string parseHost(const std::string& url) {
    const std::regex host_regex(R"(^(?:http[s]?://)?([^:/\s]+))");
    std::smatch match;
    if (std::regex_search(url, match, host_regex)) {
        return match.str(1);
    }
    return "";
}

bool isSubdomain(const std::string& parsedHost, const std::string& targetHost) {
    return parsedHost == targetHost || (parsedHost.length() > targetHost.length() &&
        parsedHost.compare(parsedHost.length() - targetHost.length(), targetHost.length(), targetHost) == 0 &&
        parsedHost[parsedHost.length() - targetHost.length() - 1] == '.');
}

std::vector<std::string> parseLinks(const std::string& responseBody, const std::string& host) {
    std::vector<std::string> foundLinks;

    const std::regex href_regex(R"(<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1)");
    const std::regex url_regex(R"((http|https)://([^\s/$.?#].[^\s]*)?)");

    auto links_begin = std::sregex_iterator(responseBody.begin(), responseBody.end(), href_regex);
    auto links_end = std::sregex_iterator();
    for (auto i = links_begin; i != links_end; ++i) {
        std::smatch match = *i;
        std::string url = match.str(2);

        if (url.find("http://") != 0 && url.find("https://") != 0) {
            if (url.front() == '/') {
                url = target::targetUrl + url;
            }
            else {
                url = target::targetUrl + "/" + url;
            }
        }

        url = sanitizeUrl(url);

        if (isValidUrl(url)) {
            std::string parsedHost = parseHost(url);
            if (parsedHost == host || isSubdomain(parsedHost, host)) {
                foundLinks.push_back(url);
            }
        }
    }

    auto plain_links_begin = std::sregex_iterator(responseBody.begin(), responseBody.end(), url_regex);
    auto plain_links_end = std::sregex_iterator();
    for (auto i = plain_links_begin; i != plain_links_end; ++i) {
        std::smatch match = *i;
        std::string url = match.str(0);

        if (url.find("http://") != 0 && url.find("https://") != 0) {
            if (url.front() == '/') {
                url = target::targetUrl + url;
            }
            else {
                url = target::targetUrl + "/" + url;
            }
        }

        url = sanitizeUrl(url);

        if (isValidUrl(url)) {
            std::string parsedHost = parseHost(url);
            if (parsedHost == host || isSubdomain(parsedHost, host)) {
                foundLinks.push_back(url);
            }
        }
    }

    return foundLinks;
}

void enforceRateLimit() {
    std::unique_lock<std::mutex> lock(rateLimitMutex);
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastRequest = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastRequestTime).count();

    if (requestsMade >= config::maxrps) {
        auto waitTime = 1000 - timeSinceLastRequest;
        if (waitTime > 0) {
            rateLimitCv.wait_for(lock, std::chrono::milliseconds(waitTime));
        }
        requestsMade = 0;
    }

    lastRequestTime = std::chrono::steady_clock::now();
    requestsMade++;
}

void workerThread() {
    const std::unordered_set<std::string> skipExtensions = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".ico",
        ".svg", ".mp4", ".mkv", ".webm", ".avi", ".mov", ".wmv",
        ".mp3", ".wav", ".flac", ".aac", ".ogg", ".pdf", ".doc",
        ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar",
        ".7z", ".tar", ".gz", ".bz2", ".exe", ".dll", ".css"
    };

    while (true) {
        dbg("Starting loop");
        std::string currentLink;

        {
            dbg("Attempting to acquire queueMutex lock for queue check...");
            std::unique_lock<std::mutex> lock(queueMutex);
            dbg("queueMutex lock acquired. Waiting on condition variable...");

            cv.wait_for(lock, std::chrono::seconds(5), [] { return !linkQueue.empty() || stopCrawling || workDone.load(); });

            if (workDone.load()) {
                dbg("Worker thread detected workDone flag. Exiting thread.");
                return;
            }

            if (stopCrawling && linkQueue.empty()) {
                dbg("Stop crawling signal received and queue is empty. Marking work as done.");
                workDone.store(true);
                cv.notify_all();
                return;
            }

            if (linkQueue.empty()) {
                dbg("Queue is empty after timeout. Checking work done...");
                workDone.store(true);
                cv.notify_all();
                return;
            }

            currentLink = linkQueue.front();
            linkQueue.pop();
            dbg("Link popped from queue: " + currentLink);

            if (linkQueue.empty() && stopCrawling) {
                dbg("Queue is empty after popping a link and stop signal received. Marking work as done.");
                workDone.store(true);
                cv.notify_all();
                return;
            }
        }

        dbg("Released queueMutex lock. Finished Queue section.");

        std::string::size_type queryPos = currentLink.find('?');
        std::string::size_type dotPos = currentLink.find_last_of('.', queryPos);

        if (dotPos != std::string::npos && (queryPos == std::string::npos || dotPos < queryPos)) {
            std::string extension = currentLink.substr(dotPos, queryPos - dotPos);
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

            if (skipExtensions.find(extension) != skipExtensions.end()) {
                dbg("Skipping link with extension: " + extension);
                checkLink(currentLink, "200");
                continue;
            }
        }

        dbg("Enforcing rate limit...");
        enforceRateLimit();

        dbg("Performing web request...");
        auto futureResult = asyncWebRequest(currentLink, config::defaultTimeout, false);
        WebRequestResult result = futureResult.get();

        if (result.status) {
            dbg("Web request succeeded. Checking link...");
            checkLink(currentLink, to_string(result.statusCode));
        }
        else {
            if (result.timedout) {
                dbg("Request timed out: " + currentLink);
                checkLink(currentLink, "200");
                {
                    dbg("Attempting to acquire rateLimitMutex lock for timeout count update...");
                    std::lock_guard<std::mutex> timeoutLock(rateLimitMutex);
                    dbg("rateLimitMutex lock acquired. Updating timeout count...");
                    target::timeoutCount++;

                    if (target::timeoutCount == 10) {
                        config::maxrps = std::max(config::maxrps / 2, 1);
                        config::defaultTimeout += 1500;
                        say("Detected time outs, reducing rate to: " + std::to_string(config::maxrps) + " and increasing timeout.");
                    }
                    else if (target::timeoutCount == 30) {
                        config::defaultTimeout += 1500;
                        config::maxrps = std::max(config::maxrps / 2, 1);
                        say("Detected time outs, reducing rate to: " + std::to_string(config::maxrps) + " and increasing timeout.");
                    }
                    else if (target::timeoutCount == 50) {
                        config::defaultTimeout += 1500;
                        config::maxrps = std::max(config::maxrps / 2, 1);
                        say("Detected time outs, reducing rate to: " + std::to_string(config::maxrps) + " and increasing timeout.");
                    }
                }
                dbg("Released rateLimitMutex lock after timeout count update.");
            }
            else {
                dbg("Web request failed: " + currentLink);
                checkLink(currentLink, "1");
            }
        }

        if (validResponse(result)) {
            dbg("Valid response received. Parsing links...");
            std::vector<std::string> newLinks = parseLinks(result.responseBody, target::host);
            {
                dbg("Attempting to acquire linkMutex lock for link parsing...");
                std::lock_guard<std::mutex> lock(linkMutex);
                dbg("linkMutex lock acquired. Inserting new links...");

                for (const auto& link : newLinks) {
                    std::string::size_type queryPos = link.find('?');
                    std::string::size_type fragmentPos = link.find('#');
                    std::string cleanLink = link.substr(0, std::min(queryPos, fragmentPos));

                    std::string::size_type dotPos = cleanLink.find_last_of('.');

                    if (dotPos != std::string::npos) {
                        std::string extension = cleanLink.substr(dotPos);
                        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

                        if (std::find(config::excludedExtensions.begin(), config::excludedExtensions.end(), extension) != config::excludedExtensions.end()) {
                            dbg("Skipping new link due to excluded extension: " + extension);
                            continue;
                        }
                    }

                    if (target::checkedLinks.find(link) == target::checkedLinks.end() &&
                        target::links.find(link) == target::links.end()) {
                        target::links.insert(link);
                        dbg("New link inserted: " + link);
                        {
                            dbg("Attempting to acquire queueMutex lock to push new link into queue...");
                            std::lock_guard<std::mutex> queueLock(queueMutex);
                            dbg("queueMutex lock acquired. Pushing new link into queue...");
                            linkQueue.push(link);
                            dbg("New link pushed into queue: " + link);
                        }
                        cv.notify_all();
                        dbg("Notified all worker threads after adding new links.");
                    }
                }
            }
            dbg("Released linkMutex lock after inserting new links.");
        }
    }
}

void crawlLinks() {
    say("Starting enumeration... please wait.");

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        for (const auto& link : target::links) {
            linkQueue.push(link);
        }
    }

    const int numThreads = config::numThreads;
    std::vector<std::thread> threads;

    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(workerThread);
    }

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    say("Enumeration completed -> " + config::outputpath);
}
