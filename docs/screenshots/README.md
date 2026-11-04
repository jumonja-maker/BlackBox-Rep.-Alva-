# UI screenshots / Скриншоты интерфейса

The PNG files in this folder are actual Windows Qt/offscreen screen captures from
successful [BLACK.BOX CI #40564970140](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/40564970140),
recorded from `main` commit `5277ffffcc308d4dee0f6d71398f9d1c04b0b1fd`.
They are **not AI-rendered mockups**, and **not real-world performance evidence**.
Screens are idle/not attached; disabled controls reflect missing prerequisites.

Файлы PNG — реальные снимки Qt/offscreen на Windows из успешного CI.
Это **не нарисованные изображения** и **не доказательства измерений
конкретного пользовательского приложения**. Серые кнопки означают, что ещё
не выбраны процесс, действие или необходимые разрешения.

Each language has Overview, Processes, Settings, Reports, Trace Decoder,
and an expanded Investigation view. The sixth decoder tab and some advanced
controls are available only in the current MAIN development build. The older
official v0.4.2 Release does **not** include these features.

Screenshots originate in the `BLACKBOX-OFFSCREEN-DPI-QA` Actions artifact.
To refresh the images after UI changes, run
`.github/workflows/readme-screenshots.yml` with a verified Windows UI/DPI
artifact and update its pinned `run-id`. Do not replace authentic screenshots
with unverified drawings or with images from third-party software.

README: [English](../../README.md) · [Русский](../../README.ru.md)

## Investigation Engine 3 (BB-INV-003, v0.5.4)

**`ru-investigation-v3-critical-path.png`** is a **different, newer screenshot**
than `ru-investigation.png` / `en-investigation.png`, which show the older
Investigation Engine 0.1.2 controls. The new image is a genuine **Russian-language**
Qt/offscreen 1024 × 720 capture from
[BB-INV-003 hosted Windows QA #41085704991](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/actions/runs/41085704991)
for source commit `41d50627c1619c2b7801db367d6ff8e1a1012122`.

It was extracted **byte-for-byte** from `word/media/rId62.png` in the
[signed-off 27-page technical report](https://github.com/jumonja-maker/BlackBox-Rep.-Alva-/blob/9454e3c97d5adb0681150009e1645a943010637f/docs/handoff/BLACKBOX-BB-INV-003-Technical-Report-41d5062.docx).
The GitHub-hosted extraction job checks the report blob SHA and screenshot
SHA-256 before committing the original image. PNG SHA-256:
`4c76511cb9fbde009a6909382a57af51ec5fb8061abbd2c70dd01045bfca6b1f`.

The view is **scrolled to Critical Path**: it shows actual BLOCKED/READY
segments and the details table, **not a complete view of all seven internal
sections or a certified root cause**. The same genuine Russian screenshot is
linked from both the Russian and English README, with accurate captions.
No UI reconstruction, edits, generated illustrations or measurement
fabrication were used.

**Русский:** снимок `ru-investigation-v3-critical-path.png` показывает
новое пространство Investigation Engine 3, а прежний
`ru-investigation.png` — инструменты Investigation 0.1.2.
Кадр подлинный, но прокручен до «Критического пути»; показанные
интервалы ожидания и готовности не удостоверяют причину зависания.
