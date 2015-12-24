#include <exception>
#include <string>

using namespace std;

class Exception : public exception {
public:
    string file, func;
    int line;
    Exception(const string &f, const string &fu, int l) : exception()
    { 
        file = f; func = fu; line = l; 
    }
    virtual ~Exception() throw() {}
};

class Out_of_Bounds: public Exception {
    Out_of_Bounds();
public:
    Out_of_Bounds(const string &f, const string &fu, int l) : Exception(f,fu,l) {}
    ~Out_of_Bounds() throw() {}
};

class Proto_Error: public Exception {
    Proto_Error();
public:
    Proto_Error(const string &f, const string &fu, int l) : Exception(f,fu,l) {}
    ~Proto_Error() throw() {}
};

class Unsupported: public Exception {
    Unsupported();
public:
    Unsupported(const string &f, const string &fu, int l) : Exception(f,fu,l) {}
    ~Unsupported() throw() {}
};


