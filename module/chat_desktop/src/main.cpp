#include "login_window.hpp"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QScopedPointer<LoginWindow> lgw(new LoginWindow);
    lgw->login(app);
    return app.exec();
}