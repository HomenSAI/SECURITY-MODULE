# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ключ восстановления на частях «2 из 3» по схеме Шамира (28.10-284 п. 2).

Реализация — проверенная библиотека pycryptodomex (`Cryptodome.Protocol.SecretSharing.Shamir`): поле GF(2^128), секрет
ровно 16 байт — это и есть ключ восстановления. Библиотека уже стоит в rent-runtime.lock (её использует pyzipper для
AES), поэтому своё конечное поле не пишется (28.10-286: криптопримитивы сами не пишем). Совместимость с библиотекой
закреплена тест-вектором в `tests/test_security_module.py`.

Свойства схемы Шамира: любые 2 части восстанавливают ключ; одна часть не даёт о нём никакой информации (каждое значение
ключа одинаково вероятно). У частей нет собственной целостности — поэтому к каждой части добавлены метка набора и
контрольная сумма (`codes.format_share`).

Метка набора (ревью DR-recovery №1) — случайная, своя у каждого выпуска (`codes.new_set_label`): метка из ключа сообщала
держателю одной части 16 бит о ключе. Части с разными метками не собираются (`shares_mismatch`); три части одного набора
сверяются между собой. Совпадение случайных меток двух наборов (1 из 65 536) при двух частях даёт неверный ключ — его
отвергает расшифровка закрытого ключа хозяйства (`recovery_wrong`), а не метка. Наборы, выданные раньше (метка = 16 бит
SHA-256 от ключа), собираются как прежде: формат части не менялся.
"""

from __future__ import annotations

from Cryptodome.Protocol.SecretSharing import Shamir

from homensai_security import codes
from homensai_security.errors import SecurityError

THRESHOLD = 2
PARTS = 3


def split(key: bytes) -> tuple[str, str, str]:
    """Три записи частей ключа восстановления для бумаги; любые две открывают."""
    if len(key) != codes.KEY_BYTES:
        raise SecurityError("recovery_format")
    tag = codes.new_set_label()
    parts = Shamir.split(THRESHOLD, PARTS, key, ssss=False)
    first, second, third = (codes.format_share(index, tag, share) for index, share in parts)
    return first, second, third


def combine_raw(parts: list[tuple[int, bytes]]) -> bytes:
    """Сборка по сырым частям (номер, 16 байт) — для тест-вектора библиотеки."""
    return bytes(Shamir.combine(parts, ssss=False))


def combine(texts: list[str] | str) -> bytes:
    """Ключ восстановления из двух (или трёх) записей частей. Одна часть — shares_needed; части разных наборов — shares_mismatch."""
    joined = "\n".join(texts) if isinstance(texts, list) else texts
    found = codes.find_shares(joined)
    unique = {index: (tag, share) for index, tag, share in found}
    if len(unique) < THRESHOLD:
        raise SecurityError("shares_needed")
    tags = {tag for tag, _share in unique.values()}
    if len(tags) != 1:
        raise SecurityError("shares_mismatch")
    ordered = sorted(unique.items())
    key = combine_raw([(index, share) for index, (_tag, share) in ordered[:THRESHOLD]])
    if len(ordered) > THRESHOLD and combine_raw([(index, share) for index, (_tag, share) in (ordered[0], ordered[2])]) != key:
        raise SecurityError("shares_mismatch")  # три части не лежат на одной прямой — смешаны наборы с одинаковой меткой
    return key


def legacy_set(texts: list[str] | str) -> bool:
    """Ревью B3 (вопрос 2, вариант 1): части собираются и их метка — прежняя, вычисленная из ключа (`codes.set_tag`). Такой
    набор сообщает держателю одной части 16 бит о ключе — показывается совет перевыпустить части, без принуждения.
    Не собираются (одна часть, опечатка, разные наборы) — False. Новый набор со случайной меткой, совпавшей с прежней
    (1 из 65 536), тоже получит совет — это безвредно."""
    try:
        key = combine(texts)
    except SecurityError:
        return False
    joined = "\n".join(texts) if isinstance(texts, list) else texts
    return {tag for _index, tag, _share in codes.find_shares(joined)} == {codes.set_tag(key)}
