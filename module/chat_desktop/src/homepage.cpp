#include <QDateTime>
#include "homepage.hpp"

HomePage::HomePage(QWidget *parent) : QMainWindow(parent)
{
    setHomePage();
    connectSignals();
}

HomePage::~HomePage() {}

void HomePage::setHomePage() {

    setWindowTitle("CHAT");
    resize(910, 600);
    splitter = new QSplitter(Qt::Horizontal, this);
    setCentralWidget(splitter);

    setNavBarList();
    setChatList();
    setContactList();
    setNavBarStackedWidget();
    setChatWindowStackedWidget();
}

void HomePage::setNavBarStackedWidget() {
    chatListStacked = new QStackedWidget(splitter);
    chatListStacked->setFixedWidth(245);
    chatListStacked->addWidget(chatList);
    chatListStacked->addWidget(contactList);
}

void HomePage::setChatWindowStackedWidget() {
    chatWindowStacked = new QStackedWidget(splitter);
    QStringList messages = {
        "Alice: Hi, how are you today?",
        "Bob: I'm good! Just finished a project.",
        "Alice: That's awesome! Let's celebrate."
    };
    for (int i = 0; i < 3; ++i) {
        ChatWindow *chatWindow = new ChatWindow(messages[i]);
        chatWindowStacked->addWidget(chatWindow);
    }
}

void HomePage::setNavBarList() {

    // ListWidgetSize: 60 = (5 + 5) * 2 + 40;   网格大小: 40;   itemSize: 35 = 5 * 2 + 25;  图片大小: 25;
    navBar = new QListWidget(splitter);
    navBar->setFixedWidth(60);
    navBar->setGridSize(QSize(40, 40));
    navBar->setIconSize(QSize(25, 25));
    navBar->setSpacing(0);
    navBar->setViewMode(QListView::IconMode);
    navBar->setMovement(QListView::Static);
    navBar->setStyleSheet(R"(
        QListWidget {
            background: #2e2e2e;
            border: none;
            outline: none;
            padding: 5px;
            margin: 5px;
        }
        QListWidget::item {
            background: #2e2e2e;
            padding: 5px;
            margin: 0;
        }
        QListWidget::item:selected {
            background: #07c160;
            border-radius: 5px;
        }
    )");
    addNavBarItems();

}

void HomePage::setChatList() {

    chatList = new QListWidget(chatListStacked);
    chatList->setFixedWidth(245);
    chatList->setSpacing(0);
    chatList->setStyleSheet(R"(
        QListWidget {
            background: #e7e6e5;
            border: none;
            outline: none;
            padding: 5px;
            margin: 5px;
        }
        QListWidget::item {
            background: #e7e6e5;
            padding: 0px;
            margin: 0px;
        }
        QListWidget::item:selected {
            background: #c6c6c6;
            border-radius: 5px;
        }
    )");
    addChatListItems();
    

}

void HomePage::setContactList() {

    contactList = new QListWidget(chatListStacked);
    contactList->setFixedWidth(245);
    contactList->setSpacing(0);
    contactList->setStyleSheet(R"(
        QListWidget {
            background: #e7e6e5;
            border: none;
            outline: none;
            padding: 5px;
            margin: 5px;
        }
        QListWidget::item {
            background: #e7e6e5;
            padding: 0px;
            margin: 0px;
        }
        QListWidget::item:selected {
            background: #c6c6c6;
            border-radius: 5px;
        }
    )");
    addContactListItems();

}

void HomePage::connectSignals() {
    connect(navBar, &QListWidget::currentRowChanged, [this](int index){
        chatListStacked->setCurrentIndex(index);
    });
    connect(chatList, &QListWidget::currentRowChanged, [this](int index){
        chatWindowStacked->setCurrentIndex(index);
    });
    
}

void HomePage::addNavBarItems() {

    QListWidgetItem *chatItem = new QListWidgetItem(QIcon(":/icons/chat.svg"), "", navBar);
    QListWidgetItem *ContactsItem = new QListWidgetItem(QIcon(":/icons/contacts.png"), "", navBar);
    QListWidgetItem *collectItem = new QListWidgetItem(QIcon(":/icons/collect.png"), "", navBar);
    QListWidgetItem *chatFilesItem = new QListWidgetItem(QIcon(":/icons/chatFiles.png"), "", navBar);
    QListWidgetItem *friendsCircleItem = new QListWidgetItem(QIcon(":/icons/friendsCircle.png"), "", navBar);
    QListWidgetItem *videoNumItem = new QListWidgetItem(QIcon(":/icons/video.png"), "", navBar);
    QListWidgetItem *takeALookItem = new QListWidgetItem(QIcon(":/icons/look.png"), "", navBar);
    QListWidgetItem *searchItem = new QListWidgetItem(QIcon(":/icons/search.png"), "", navBar);

    chatItem->setSizeHint(QSize(35, 35));
    ContactsItem->setSizeHint(QSize(35, 35));
    collectItem->setSizeHint(QSize(35, 35));
    chatFilesItem->setSizeHint(QSize(35, 35));
    friendsCircleItem->setSizeHint(QSize(35, 35));
    videoNumItem->setSizeHint(QSize(35, 35));
    takeALookItem->setSizeHint(QSize(35, 35));
    searchItem->setSizeHint(QSize(35, 35));

    chatItem->setToolTip("聊天");
    ContactsItem->setToolTip("通讯录");
    collectItem->setToolTip("收藏");
    chatFilesItem->setToolTip("聊天文件");
    friendsCircleItem->setToolTip("朋友圈");
    videoNumItem->setToolTip("视频号");
    takeALookItem->setToolTip("看一看");
    searchItem->setToolTip("搜一搜");
}

void HomePage::addChatListItems() {

    QStringList senders = {"Charlie", "Alice", "Bob"};
    QStringList messages = {
        "Did you finish the project?",
        "Yes, I just submitted it.",
        "Great, let's celebrate!"
    };
    QStringList timestamps = {
        QDateTime::currentDateTime().toString("hh:mm AP"),
        QDateTime::currentDateTime().addSecs(120).toString("hh:mm AP"),
        QDateTime::currentDateTime().addSecs(240).toString("hh:mm AP"),
        QDateTime::currentDateTime().addSecs(360).toString("hh:mm AP"),
        QDateTime::currentDateTime().addSecs(480).toString("hh:mm AP")
    };

    for (int i = 0; i < 3; ++i) {
        QString chatEntry = QString("[%1] \n%2: %3").arg(timestamps[i], senders[i], messages[i]);
        QString picture = ":/icons/person_%1";
        CustomWidget *widget = new CustomWidget(truncateText(chatEntry, chatList->width() - 10, chatList->font()), chatList);
        widget->setIconSize(QIcon(picture.arg(i+1)), 35, 35);
        widget->setTextLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        widget->setTextLabelFixedLengthWidth(160, 35);
        widget->setIconLabelFixedLengthWidth(35, 35);
        QListWidgetItem *item = new QListWidgetItem();
        item->setSizeHint(QSize(chatList->width()-20, 55));
        chatList->addItem(item);
        chatList->setItemWidget(item, widget);
    }

}

void HomePage::addContactListItems() {

    QStringList contacts = {"John", "Emily", "Michael"};
    for (int i = 0; i < 3; ++i) {
        QString chatEntry = QString(contacts[i]);
        QString picture = ":/icons/person_%1";
        CustomWidget *widget = new CustomWidget(truncateText(chatEntry, contactList->width() - 10, contactList->font()), contactList);
        widget->setIconSize(QIcon(picture.arg(i+4)), 35, 35);
        widget->setTextLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        widget->setTextLabelFixedLengthWidth(160, 35);
        widget->setIconLabelFixedLengthWidth(35, 35);
        QListWidgetItem *item = new QListWidgetItem();
        // qDebug() << "item size:" << contactList->width();
        item->setSizeHint(QSize(contactList->width()-20, 55));
        contactList->addItem(item);
        contactList->setItemWidget(item, widget);
    }

}

QString HomePage::truncateText(const QString &text, int maxWidth, const QFont &font) {
    QFontMetrics metrics(font);
    return metrics.elidedText(text, Qt::ElideRight, maxWidth);
}