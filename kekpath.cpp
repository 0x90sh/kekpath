#include "kekpath.h"

int main(int argc, char* argv[]) {
    string url;
    string port = "80";
    string ua;
    string tmout;
    string threads;
    string rate;
    string networkInterface;
    string outputPath;

    if (argc == 2 && (string(argv[1]) == "-h" || string(argv[1]) == "-help")) {
        cout << "=============================================================\n";
        cout << " kekpath - Recursive Web Scanner\n";
        cout << "=============================================================\n";
        cout << "Usage: " << argv[0] << " [OPTIONS]\n";
        cout << "Options:\n";
        cout << "  -u <URL>         : Set the target URL (required)\n";
        cout << "  -p <PORT>        : Set the port number (default: 80)\n";
        cout << "  -excl <EXTS>     : Exclude certain file extensions (comma-separated, e.g., .php,.js)\n";
        cout << "  -t <TIMEOUT>     : Set the request timeout in milliseconds (500-10000)\n";
        cout << "  -ua <USER_AGENT> : Set the User-Agent string (or use 'rand' for random)\n";
        cout << "  -dbg             : Enable debug mode\n";
        cout << "  -tr <THREADS>    : Set the number of threads (1-5)\n";
        cout << "  -rl <RATE>       : Set the max request rate per second (1-50)\n";
        cout << "  -n <INTERFACE>   : Specify the network interface to use\n";
        cout << "  -o <OUTPUT>      : Specify the output file path or filename (.txt file)\n";
        cout << "  -h, -help        : Show this help message\n";
        cout << "=============================================================\n";
        return 0;
    }


    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];

        if (arg == "-u" && i + 1 < argc) {
            url = argv[++i];
            if (!isValidUrl(url)) {
                say("Invalid URL. Please provide a valid URL starting with http:// or https://.", "err");
                return 1;
            }
        }
        else if (arg == "-p" && i + 1 < argc) {
            port = argv[++i];
            if (!isValidPort(port)) {
                say("Invalid port. Please provide a valid port number between 1 and 65535.", "err");
                return 1;
            }
        }
        else if (arg == "-excl" && i + 1 < argc) {
            string extensions = argv[++i];
            size_t pos = 0;
            while ((pos = extensions.find(',')) != std::string::npos) {
                config::excludedExtensions.push_back(extensions.substr(0, pos));
                extensions.erase(0, pos + 1);
            }

            if (!extensions.empty()) {
                config::excludedExtensions.push_back(extensions);
            }

            dbg("Excluded extensions:");
            for (const auto& ext : config::excludedExtensions) {
                dbg(" - " + ext);
            }
        }
        else if (arg == "-t" && i + 1 < argc) {
            tmout = argv[++i];
            try {
                long timeout = std::stol(tmout);
                if (timeout < 500 || timeout > 10000) {
                    say("Timeout must be between 500 and 10000 milliseconds.", "err");
                    return 1;
                }
                config::defaultTimeout = timeout;
                dbg("Timeout set to " + to_string(config::defaultTimeout) + " milliseconds");
            }
            catch (const std::invalid_argument&) {
                say("Invalid timeout value. Please provide a valid number.", "err");
                return 1;
            }
            catch (const std::out_of_range&) {
                say("Timeout value out of range. Please provide a value between 500 and 10000 milliseconds.", "err");
                return 1;
            }
        }
        else if (arg == "-ua" && i + 1 < argc) {
            ua = argv[++i];
            if (ua == "random" || ua == "r" || ua == "rand") {
                config::ua = "rand";
            }
            else if (!ua.empty()) {
                config::ua = ua;
            }
            else {
                config::ua = "default";
            }
        }
        else if (arg == "-dbg") {
            config::debug = true;
        }
        else if (arg == "-tr" && i + 1 < argc) {
            threads = argv[++i];
            try {
                int numThreads = std::stoi(threads);
                if (numThreads < 1 || numThreads > 5) {
                    say("Number of threads must be between 1 and 5.", "err");
                    return 1;
                }
                config::numThreads = numThreads;
                dbg("Number of threads set to " + to_string(config::numThreads));
            }
            catch (const std::invalid_argument&) {
                say("Invalid number of threads. Please provide a valid number.", "err");
                return 1;
            }
            catch (const std::out_of_range&) {
                say("Number of threads out of range. Please provide a value between 1 and 32.", "err");
                return 1;
            }
        }
        else if (arg == "-rl" && i + 1 < argc) {
            rate = argv[++i];
            try {
                int nrate = std::stoi(rate);
                if (nrate < 1 || nrate > 50) {
                    say("Rate must be between 1 and 50.", "err");
                    return 1;
                }
                config::maxrps = nrate;
                dbg("Number of rq/s set to " + to_string(config::maxrps));
            }
            catch (const std::invalid_argument&) {
                say("Invalid rate value. Please provide a valid number.", "err");
                return 1;
            }
            catch (const std::out_of_range&) {
                say("Number of rq/s out of range. Please provide a value between 1 and 50.", "err");
                return 1;
            }
        }
        else if (arg == "-n" && i + 1 < argc) {
            networkInterface = argv[++i];
            config::network_interface = networkInterface;
            dbg("Network interface set to " + config::network_interface);
        }
        else if (arg == "-o" && i + 1 < argc) {
            outputPath = argv[++i];

            if (outputPath.empty() || outputPath.find(".txt") == std::string::npos) {
                say("Invalid output file. Please provide a valid .txt file.", "err");
                return 1;
            }

            if (outputPath.find("/") == std::string::npos && outputPath.find("\\") == std::string::npos) {
                std::string currentPath = std::filesystem::current_path().string();
                config::outputpath = currentPath + "/" + outputPath;
            }
            else {
                config::outputpath = outputPath;
            }

            dbg("Output path set to: " + config::outputpath);
            }
        else {
            say("Unknown or malformed argument: " + arg, "err");
            return 1;
        }
    }
    if (config::outputpath.empty()) {
        setOutputPath();
    }

    if (url.empty()) {
        say("The -u argument (URL) is required.", "err");
        return 1;
    }

    dbg("Parsing URL: " + url);
    string protocol, host, path;
    parseUrl(url, protocol, host, path);

    target::protocol = protocol;
    target::host = host;
    target::port = port;
    target::startingPath = path;

    dbg("Parsed URL details: Protocol = " + protocol + ", Host = " + host + ", Port = " + port + ", Path = " + path);

    if (target::port == "80" && target::protocol == "https") target::port = "443";

    if (target::port == "80" || target::port == "443") {
        target::targetUrl = protocol + "://" + host;
    }
    else {
        target::targetUrl = protocol + "://" + host + ":" + port;
    }

    dbg("Constructed target URL: " + target::targetUrl);

    while (true) {
        say("Checking if " + target::targetUrl + target::startingPath + " is alive...");

        WebRequestResult result = performWebRequest(target::targetUrl + target::startingPath, config::defaultTimeout);

        if (!result.status) {
            say("Your target is dead!", "err");
            dbg("Target did not respond.");
            return 1;
        }

        dbg("Dumping request result...");
        printRequestDump(result);

        if (result.statusCode >= 300 && result.statusCode < 400) {
            if (!isValidUrl(result.redirectUrl)) {
                say("Invalid redirection URL, can't follow!", "err");
                dbg("Invalid redirection URL detected: " + result.redirectUrl);
                return 1;
            }
            string follow_input = say("Want to follow (" + result.redirectUrl + ") and continue? (y/n)", "get");
            dbg("User input for redirection follow: " + follow_input);

            if (!(follow_input == "y" || follow_input == "Y" || follow_input == "Yes" || follow_input == "yes")) {
                say("Not following redirection...", "err");
                dbg("Redirection not followed.");
                return 0;
            }

            string protocol_new, host_new, path_new;
            parseUrl(result.redirectUrl, protocol_new, host_new, path_new);
            target::protocol = protocol_new;
            target::host = host_new;
            target::startingPath = path_new;

            dbg("Parsed redirection URL: Protocol = " + protocol_new + ", Host = " + host_new + ", Path = " + path_new);

            if (target::port == "80" || target::port == "443") {
                target::targetUrl = protocol_new + "://" + host_new;
            }
            else {
                target::targetUrl = protocol_new + "://" + host_new + ":" + target::port;
            }

            dbg("Constructed new target URL after redirection: " + target::targetUrl);
        }
        else if (result.statusCode < 200 || result.statusCode >= 300) {
            say("Request failed based on status code.", "err");
            dbg("Request failed with status code: " + to_string(result.statusCode));
            return 0;
        }
        else {
            say("Target alive, let's get started...");
            dbg("Target responded successfully with status code: " + to_string(result.statusCode));
            break;
        }
    }

    if (target::startingPath == "" || target::startingPath == " ") target::startingPath = "/";

    if (config::maxrps > 5) {
        bool clean = probeTarget(target::targetUrl + target::startingPath);
        if (clean) {
            string start = say("Probing finished, start enumaration? (y/n)", "get");
            if (!(start == "y" || start == "Y" || start == "Yes" || start == "yes")) {
                say("Enumaration aborted!", "err");
                return 0;
            }
        }
        else {
            say("Ratelimit detected, it is adviced to wait a few seconds... (press enter)", "get");
            string start = say("Probing finished, start enumaration? (y/n)", "get");
            if (!(start == "y" || start == "Y" || start == "Yes" || start == "yes")) {
                say("Enumaration aborted!", "err");
                return 0;
            }
        }
    }

    calcAttackVector();

    crawlLinks();

    return 0;
}