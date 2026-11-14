# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""«Аварийный лист» PDF (28.10-279 п. 1; образец — Emergency Kit 1Password).

На листе: отпечаток ключа хозяйства (HR1) и ключа подписи цепочки (HS1) с QR, ключ восстановления (если создан вместе с
листом), поле, чтобы вписать пароль от руки, и пошаговая инструкция восстановления на другом ПК. Пароль печатается только
по явному выбору (`SheetData.password`). Тексты — данные `TEXTS` на двух языках; лист строится из строк `sheet_lines`, PDF
лишь раскладывает их (ReportLab), поэтому содержимое проверяется без разбора PDF.

Шрифт с кириллицей: каталог с IBM Plex передаёт вызывающий (`font_dir`); без него — встроенный Helvetica (кириллица не
отрисуется, лист остаётся читаемым по отпечаткам и ключу).
"""

from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path
import re

_CODE_LINE = re.compile(r"[0-9A-Z]{5}-[0-9A-Z]{5}")

TEXTS: dict[str, dict[str, str]] = {
    "ru": {
        "title": "Аварийный лист HomenS.AI Rent — копии",
        "issued": "Выдан: {at}",
        "keep": "Храните лист в сейфе, вдали от ПК. Кто держит лист и копию — может открыть копию.",
        "household": "Отпечаток ключа хозяйства: {fp}",
        "signing": "Отпечаток ключа подписи цепочки: {fp}",
        "recovery": "Ключ восстановления «{name}»: {key}",
        "recovery_none": "Ключ восстановления: ______________________________ (впишите, если создан отдельно)",
        "password": "Пароль копий: {password}",
        "password_blank": "Пароль копий: ________________________________",
        "steps": "Как восстановить на другом ПК:",
        "step1": "1. Установите HomenS.AI Rent и найдите свежую копию: папка HomensaiRent/Копии/ГГГГ/ММ или канал Telegram.",
        "step2": "2. Запустите «python -m app.ctl restore» и укажите файл копии.",
        "step3": "3. Введите пароль копий. Забыли пароль — введите ключ восстановления (RK1-…) или две части ключа (RS1-…).",
        "step4": "4. Сверьте отпечатки HR1 и HS1 на экране «Защита копий» с этим листом.",
        "step5": "5. После восстановления задайте новый пароль копий и распечатайте новый лист.",
        "codes": "Коды восстановления входа (каждый — один раз, вместо ключа или Google Authenticator):",
    },
    "uk": {
        "title": "Аварійний лист HomenS.AI Rent — копії",
        "issued": "Видано: {at}",
        "keep": "Зберігайте лист у сейфі, подалі від ПК. Хто тримає лист і копію — може відкрити копію.",
        "household": "Відбиток ключа господарства: {fp}",
        "signing": "Відбиток ключа підпису ланцюжка: {fp}",
        "recovery": "Ключ відновлення «{name}»: {key}",
        "recovery_none": "Ключ відновлення: ______________________________ (впишіть, якщо створено окремо)",
        "password": "Пароль копій: {password}",
        "password_blank": "Пароль копій: ________________________________",
        "steps": "Як відновити на іншому ПК:",
        "step1": "1. Встановіть HomenS.AI Rent і знайдіть свіжу копію: тека HomensaiRent/Копії/РРРР/ММ або канал Telegram.",
        "step2": "2. Запустіть «python -m app.ctl restore» і вкажіть файл копії.",
        "step3": "3. Введіть пароль копій. Забули пароль — введіть ключ відновлення (RK1-…) або дві частини ключа (RS1-…).",
        "step4": "4. Звірте відбитки HR1 і HS1 на екрані «Захист копій» з цим листом.",
        "step5": "5. Після відновлення задайте новий пароль копій і роздрукуйте новий лист.",
        "codes": "Коди відновлення входу (кожен — один раз, замість ключа або Google Authenticator):",
    },
}


@dataclass(frozen=True)
class SheetData:
    household_fingerprint: str | None
    signing_fingerprint: str | None
    recovery_text: str | None = None
    issued_at: str = ""
    password: str | None = None  # только по явному выбору пользователя
    recovery_name: str = ""
    login_codes: tuple[str, ...] = ()  # 28.10-284: новый набор кодов входа, выпущенный вместе с листом (старые хэши не печатаются)


def sheet_lines(data: SheetData, lang: str = "ru") -> list[str]:
    t = TEXTS.get(lang, TEXTS["ru"])
    lines = [t["title"], t["issued"].format(at=data.issued_at), t["keep"], ""]
    lines.append(t["household"].format(fp=data.household_fingerprint or "—"))
    lines.append(t["signing"].format(fp=data.signing_fingerprint or "—"))
    lines.append("")
    if data.recovery_text:
        lines.append(t["recovery"].format(name=data.recovery_name or "—", key=data.recovery_text))
    else:
        lines.append(t["recovery_none"])
    lines.append(t["password"].format(password=data.password) if data.password else t["password_blank"])
    lines += ["", t["steps"], t["step1"], t["step2"], t["step3"], t["step4"], t["step5"]]
    if data.login_codes:
        lines += ["", t["codes"]]
        codes = list(data.login_codes)
        lines += [f"{i + 1:>2}. {codes[i]}" + (f"    {i + 2:>2}. {codes[i + 1]}" if i + 1 < len(codes) else "") for i in range(0, len(codes), 2)]
    return lines


def qr_payload(data: SheetData) -> str:
    """Что в QR: только отпечатки (секретов в QR нет) — для сверки камерой телефона."""
    return f"HOMENSAI-RENT;{data.household_fingerprint or '-'};{data.signing_fingerprint or '-'}"


def _fonts(font_dir: Path | None) -> tuple[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    if font_dir is None:
        candidate = Path(__file__).resolve().parents[2] / "render" / "fonts"  # при переносе в модуль шрифты поедут с ним
        font_dir = candidate if candidate.is_dir() else None
    if font_dir is not None and (font_dir / "IBMPlexSans-Regular.ttf").is_file():
        for name, file in (("SecSheet", "IBMPlexSans-Regular.ttf"), ("SecSheetMono", "IBMPlexMono-Regular.ttf")):
            if name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(name, str(font_dir / file)))
        return "SecSheet", "SecSheetMono"
    return "Helvetica", "Courier"


def emergency_sheet_pdf(data: SheetData, lang: str = "ru", font_dir: Path | None = None) -> bytes:
    """PDF A4 одной страницей. Пароль попадает на лист только если задан `data.password`."""
    from reportlab.graphics import renderPDF
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    regular, mono = _fonts(font_dir)
    buffer = io.BytesIO()
    page = canvas.Canvas(buffer, pagesize=A4, pageCompression=1)
    page.setTitle(TEXTS.get(lang, TEXTS["ru"])["title"])
    width, height = A4
    y = height - 25 * mm
    for index, line in enumerate(sheet_lines(data, lang)):
        is_code = any(marker in line for marker in ("HR1-", "HS1-", "RK1-", "____")) or bool(_CODE_LINE.search(line))
        page.setFont(mono if is_code else regular, 15 if index == 0 else 10.5)
        page.drawString(20 * mm, y, line)
        y -= 9 * mm if index == 0 else 7 * mm
    widget = QrCodeWidget(qr_payload(data))
    left, bottom, right, top = widget.getBounds()
    size = 42 * mm
    drawing = Drawing(size, size, transform=[size / (right - left), 0, 0, size / (top - bottom), 0, 0])
    drawing.add(widget)
    renderPDF.draw(drawing, page, width - 20 * mm - size, height - 20 * mm - size)
    page.showPage()
    page.save()
    return buffer.getvalue()
