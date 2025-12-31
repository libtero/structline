import json, os, re
from typing import cast
from enum import IntEnum

from PySide6.QtCore import *
from PySide6.QtWidgets import *
from PySide6.QtGui import *
from PySide6.QtCore import *

import ida_kernwin, idc, idautils, ida_idaapi, ida_typeinf, ida_hexrays, ida_diskio

HIST_LEN = 15
HINT_FONT = "monospaced"
HIST_PATH = os.path.join(ida_diskio.get_user_idadir(), "strucline_history.json")
DECOMP_TYPES = ["_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD", "_TBYTE", "_UNKNOWN"]


class LastStructSingleton():
    _instance = None
    name: str

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.name = str()
        return cls._instance


_LSTRUC = LastStructSingleton()


def parseOffset(arg: str) -> int:
    for suffix in ["h", "LL", "u"]:
        arg = arg.rstrip(suffix)
    return int(arg, 16)


def addSuffixIfTaken(struc_id: int, mem_name: str) -> str:
    i = 1
    while idc.get_member_offset(struc_id, mem_name) != -1:
        mem_name = "{}_{}".format(mem_name, i)
        i += 1
    return mem_name


def getLvarType(widget) -> ida_typeinf.tinfo_t | None:
    try:
        vdui = ida_hexrays.get_widget_vdui(widget)
        cit = vdui.item.it
        lvars = vdui.cfunc.get_lvars()
        idx = cit.cexpr.get_v().idx
        return lvars[idx].tif
    except:
        pass
    return None


def clearTypePointer(tif: ida_typeinf.tinfo_t) -> ida_typeinf.tinfo_t:
    while tif.is_ptr():
        tif = tif.get_pointed_object()
    return tif


def getCursorPointedType() -> str:
    token = str()
    if widget := ida_kernwin.get_current_widget():
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            if var_tif := getLvarType(widget):
                return str(clearTypePointer(var_tif))
        else:
            if token := ida_kernwin.get_highlight(widget, 0):
                return token[0]
    return token


def tryCursorAsStruct() -> str:
    if name := getCursorPointedType():
        if idc.get_struc_id(name) != idc.BADADDR:
            return name
    return str()


def tryCursorAsOffset() -> str:
    if hl := getCursorPointedType():
        try:
            parseOffset(hl)
            return hl.lstrip("0").strip()
        except:
            pass
    return str()


def getType(type_name: str) -> ida_typeinf.tinfo_t:
    tif = ida_typeinf.tinfo_t()  # type: ignore
    tif.parse(type_name, pt_flags=ida_typeinf.PT_SIL)
    return tif


def isValidMemberName(name: str) -> bool:
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name))


def isTypeValid(type_name: str) -> bool:
    return len(str(getType(type_name))) > 0


def getOverlappedMemberNames(struc_name: str, off: int, size: int) -> list[tuple]:
    struc_id = idc.get_struc_id(struc_name)
    names: list[tuple] = list()
    added_names = list()
    got_roff = False
    for i in range(size):
        name = idc.get_member_name(struc_id, off + i)
        if name and not name in added_names and not name.startswith("gap"):
            roff = off + i
            if not got_roff:
                roff = idc.get_member_offset(struc_id, name)
                got_roff = True
            names.append((roff, name))
            added_names.append(name)
    return names


def getDatabaseHash() -> str:
    return idautils.GetInputFileMD5().hex().lower()


class History:
    def __init__(self, file_path: str):
        self.path = file_path
        self.idbHash = getDatabaseHash()
        if not os.path.exists(self.path):
            self.createHistoryFile()
        self.allHistory = self.loadHistory() or dict()
        self.currHistory = self.allHistory.get(self.idbHash, list())[:HIST_LEN - 1]

    def cleanHistory(self):
        history = list()
        for ln in self.currHistory:
            if not len(history) or ln not in history:
                history.append(ln)
        self.currHistory = history

    def saveHistory(self):
        self.cleanHistory()
        if len(self.currHistory) == 0:
            return
        self.allHistory[self.idbHash] = self.currHistory
        try:
            with open(self.path, "w") as fh:
                data = json.dumps(self.allHistory, indent=4)
                fh.write(data)
        except:
            ida_kernwin.warning("Structliner:\nCouldn't save history file.")

    def loadHistory(self, fallback=False) -> dict | None:
        try:
            with open(self.path, "r") as fh:
                data = fh.read()
        except:
            ida_kernwin.warning("Structliner:\nCouldn't load history file.")
            return None
        try:
            data = json.loads(data)
            assert isinstance(data, dict)
            return data
        except:
            if fallback:
                return None
            if ida_kernwin.ask_yn(0,
                                  "Structliner:\nCouldn't parse history file. \
                                  Do you want to create new one ?") == 1:
                self.createHistoryFile()
                self.loadHistory(True)

    def createHistoryFile(self):
        try:
            with open(self.path, "w") as fh:
                fh.write("{}")
        except:
            pass


def getStructNamesList() -> list[str]:
    return [s[2] for s in idautils.Structs()]


def getTypeNamesList() -> list[str]:
    til = ida_typeinf.get_idati()
    ntypes = ida_typeinf.get_ordinal_count()
    type_names = [ida_typeinf.get_numbered_type_name(til, i) for i in range(ntypes + 1)]
    return [name for name in type_names if name] + DECOMP_TYPES


class Styles:
    _style = "border: 2px solid {};"
    INVALID = _style.format("orangered")
    VALID = _style.format("lawngreen")
    ALERT_MEMBER = _style.format("gold")
    ALERT_STRUCT = _style.format("deepskyblue")
    HINT = "<span style='color:#808080;'>{:08X}</span>    <span style='color:#8082F7'>{}</span>"


class InputStatus(IntEnum):
    INVALID = 0
    VALID = 1
    ALERT_MEMBER = 2
    ALERT_STRUCT = 3


class SQWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.structNames = getStructNamesList()
        self.typeNames = getTypeNamesList()
        self.history = History(HIST_PATH)
        self.historyLines = self.history.currHistory
        self.addMainLayout()
        self.addQLineLayout()
        self.addOverlapHint()
        self.status: InputStatus
        self.historyIdx = 0
        self.inputField: QLineEdit
        self.structName: str
        self.memberOff: int
        self.memberType: str
        self.memberName: str
        self.overlapsMembers: bool
        self.hint: QLabel

    def addMainLayout(self):
        self.setWindowTitle("Structline")
        self.setFixedSize(500, 80)
        self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.mainLayout: QBoxLayout = QVBoxLayout()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setLayout(self.mainLayout)

    def createQLineEdit(self):
        line = QLineEdit(self)
        completer = QCompleter(self.structNames)
        completer.setCompletionMode(QCompleter.CompletionMode.InlineCompletion)
        line.setCompleter(completer)
        line.setFixedHeight(28)
        line.setPlaceholderText("struct.name | member.offset | member.type | member.name")
        line.installEventFilter(self)
        if text := tryCursorAsStruct() or _LSTRUC.name:
            text += " "
            if mem_off := tryCursorAsOffset():
                text += mem_off + " "
            line.setText(text)
        self.historyLines.insert(0, line.text())
        return line

    def addOverlapHint(self):
        hint = QLabel(self)
        hint.setStyleSheet(f"background-color: #FFFFE4; font-family: {HINT_FONT};")
        hint.setWindowFlags(Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint)
        hint.setFixedWidth(460)
        self.hint = hint

    def addQLineLayout(self):
        layout = QHBoxLayout()
        self.inputField = self.createQLineEdit()
        layout.addWidget(self.inputField)
        self.mainLayout.addLayout(layout)
        self.inputField.textChanged.connect(self.inputTextChanged)

    def logStructAdded(self, mem_name: str):
        print("Added {} {} @ 0x{:X} for {}".format(str(getType(self.memberType)), mem_name, self.memberOff,
                                                   self.structName))

    def addStrucMember(self):
        action_name = "structline:commit"

        class CommitHandler(ida_kernwin.action_handler_t):
            def __init__(self, callback):
                ida_kernwin.action_handler_t.__init__(self)
                self.callback = callback

            def activate(self, ctx):
                self.callback()
                return 1

            def update(self, ctx):
                return ida_kernwin.AST_ENABLE_ALWAYS

        if not ida_kernwin.unregister_action(action_name):
            pass
        desc = ida_kernwin.action_desc_t(
            action_name,
            "Strucline: Commit struct change",
            CommitHandler(self._addStrucMember)
        )
        ida_kernwin.register_action(desc)
        ida_kernwin.process_ui_action(action_name)

    def _addStrucMember(self):
        _LSTRUC.name = self.structName
        struc_id = idc.get_struc_id(self.structName)
        if struc_id == idc.BADADDR:
            struc_id = idc.add_struc(-1, self.structName, 0)
        else:
            for i in range(getType(self.memberType).get_size()):
                idc.del_struc_member(struc_id, self.memberOff + i)
        mem_name = addSuffixIfTaken(struc_id, self.memberName)
        mem_type = getType(self.memberType)
        tif = getType(self.structName)
        struc_size = tif.get_size()
        if self.memberOff > struc_size:
            tif.add_udm(mem_name, mem_type, struc_size * 8)  # type: ignore
            idc.expand_struc(struc_id, struc_size, self.memberOff - struc_size)
        else:
            tif.add_udm(mem_name, mem_type, self.memberOff * 8)  # type: ignore
        self.logStructAdded(mem_name)

    def getTypeCompletion(self, tokens: list[str]) -> list[str]:
        ctext = " ".join(tokens[:2]) + " "
        candidates = [type_name for type_name in self.typeNames if type_name.startswith(tokens[2])]
        return [ctext + cand for cand in candidates]

    def setCompleterWords(self, tokens: list[str]):
        ntokens = len(tokens)
        if ntokens == 2:
            cast(QStringListModel, self.inputField.completer().model()).setStringList(self.structNames)
        elif ntokens == 3:
            words = self.getTypeCompletion(tokens)
            cast(QStringListModel, self.inputField.completer().model()).setStringList(words)

    def validateParseInput(self):
        new_struct = False
        has_valid_type = True
        self.status = InputStatus.INVALID
        self.overlapsMembers = False
        try:
            text = self.inputField.text()
            tokens = text.replace(",", "").split()
        except:
            return
        ntokens = len(tokens)
        if not 1 <= ntokens <= 4:
            return
        if (struc_id := idc.get_struc_id(tokens[0])) == idc.BADADDR:
            new_struct = True
        if not new_struct:
            _LSTRUC.name = tokens[0]
        try:
            mem_off = parseOffset(tokens[1])
        except:
            return
        if not new_struct:
            mem_name = idc.get_member_name(struc_id, mem_off)
            self.overlapsMembers = mem_name is not None and not mem_name.startswith("gap")
        self.status = InputStatus.VALID
        self.setCompleterWords(tokens)
        if new_struct:
            self.status = InputStatus.ALERT_STRUCT
        if ntokens == 2:
            self.memberType = "_BYTE"
        else:
            if not isTypeValid(tokens[2]):
                self.status = InputStatus.INVALID
                has_valid_type = False
            else:
                self.memberType = tokens[2]
        if has_valid_type:
            if overlapped := getOverlappedMemberNames(tokens[0], mem_off, getType(self.memberType).get_size()):
                self.status = InputStatus.ALERT_MEMBER
                lines = [Styles.HINT.format(var[0], var[1]) for var in overlapped]
                self.hint.setText("<br>".join(lines))
                self.overlapsMembers = True
        if ntokens == 4:
            if isValidMemberName(tokens[3]):
                self.memberName = tokens[3]
            else:
                self.status = InputStatus.INVALID
        else:
            self.memberName = "field_{:X}".format(mem_off)
        self.structName = tokens[0]
        self.memberOff = mem_off

    def hideHint(self):
        self.hint.hide()

    def showHint(self):
        QTimer.singleShot(5, self.hint.adjustSize)
        QTimer.singleShot(5, self.updateHintPosition)
        QTimer.singleShot(100, self.hint.show)
        QTimer.singleShot(100, self.hint.raise_)

    def inputTextChanged(self):
        self.validateParseInput()
        if self.overlapsMembers:
            self.showHint()
        else:
            self.hideHint()
        match self.status:
            case InputStatus.INVALID:
                self.inputField.setStyleSheet(Styles.INVALID)
            case InputStatus.VALID:
                self.inputField.setStyleSheet(Styles.VALID)
            case InputStatus.ALERT_MEMBER:
                self.inputField.setStyleSheet(Styles.ALERT_MEMBER)
            case InputStatus.ALERT_STRUCT:
                self.inputField.setStyleSheet(Styles.ALERT_STRUCT)
            case _:
                raise Exception("inputTextChanged(): unknown InputStatus")

    def keyPressEvent(self, event: QKeyEvent):
        if event.key() == Qt.Key.Key_Escape:
            self.historyLines.pop(0)
            text = self.inputField.text()
            if (not text) or (text and _LSTRUC.name and not _LSTRUC.name in text):
                _LSTRUC.name = None
            self.close()

        super().keyPressEvent(event)

    def eventFilter(self, watched, event: QEvent):
        if event.type() == QEvent.Type.KeyPress:
            event = cast(QKeyEvent, event)
            match event.key():
                case Qt.Key.Key_Return:
                    if self.status != InputStatus.INVALID:
                        self.addStrucMember()
                        self.historyLines[0] = self.inputField.text()
                        self.close()
                    return True

                case Qt.Key.Key_Tab:
                    if self.inputField.hasSelectedText():
                        self.inputField.setCursorPosition(self.inputField.selectionEnd())
                    return True

                case Qt.Key.Key_Up:
                    if self.historyLines:
                        self.historyIdx = min(len(self.historyLines) - 1, self.historyIdx + 1)
                        self.inputField.setText(self.historyLines[self.historyIdx])
                    return True

                case Qt.Key.Key_Down:
                    if self.historyLines:
                        self.historyIdx = max(self.historyIdx - 1, 0)
                        self.inputField.setText(self.historyLines[self.historyIdx])
                    return True
        return False

    def updateHintPosition(self):
        global_pos = self.inputField.mapToGlobal(QPoint(0, self.inputField.height() + 1))
        self.hint.move(global_pos)

    def event(self, event: QEvent):
        if event.type() == QEvent.Type.NonClientAreaMouseButtonRelease:
            if self.overlapsMembers:
                self.showHint()
        elif event.type() == QEvent.Type.NonClientAreaMouseButtonPress:
            self.hideHint()
        return super().event(event)

    def changeEvent(self, event):
        if event.type() == QEvent.Type.ActivationChange:
            if not self.isActiveWindow():
                self.hideHint()
            elif self.overlapsMembers:
                self.showHint()
        super().changeEvent(event)

    def show(self):
        self.inputTextChanged()
        super().show()
        self.updateHintPosition()

    def close(self):
        self.hint.close()
        super().close()
        self.history.saveHistory()
        return True


class Structline(ida_idaapi.plugin_t):
    wanted_name = "Structline"
    wanted_hotkey = "F"
    flags = 0

    def init(self):
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.widget = SQWidget()
        self.widget.show()
        self.widget.setFocus()
        self.widget.inputField.setFocus()


def PLUGIN_ENTRY():
    return Structline()  # type: ignore
