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
