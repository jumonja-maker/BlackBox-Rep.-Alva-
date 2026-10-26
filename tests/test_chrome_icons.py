import os
import unittest
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from PySide6.QtCore import QSize
from PySide6.QtWidgets import QApplication
from blackbox_universal.chrome_icons import ChromeButton,SYMBOLS,icon

class VectorChromeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])
    def test_every_actual_chrome_icon_has_visible_pixels_without_a_font(self):
        for symbol in SYMBOLS:
            image=icon(symbol).pixmap(QSize(28,28)).toImage()
            self.assertFalse(image.isNull(),symbol)
            self.assertTrue(any(image.pixelColor(x,y).alpha()>0 for x in range(28) for y in range(28)),symbol)
    def test_translated_button_preserves_original_key_and_vector(self):
        b=ChromeButton('▶  START OBSERVING')
        b.setText('▶  НАЧАТЬ НАБЛЮДЕНИЕ')
        self.assertEqual(b.property('bb_english'),'▶  START OBSERVING')
        self.assertEqual(b.text(),'НАЧАТЬ НАБЛЮДЕНИЕ');self.assertFalse(b.icon().isNull())
