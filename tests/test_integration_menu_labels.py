"""Retain menu actions/translation keys while preventing duplicated indicators."""
import os
import unittest
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from PySide6.QtWidgets import QApplication,QMenu,QHBoxLayout,QWidget
from blackbox_universal.chrome_icons import ChromeButton
from blackbox_universal.theme import set_retro_theme


class MenuLabelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=QApplication.instance() or QApplication([])
        set_retro_theme(cls.app)

    def test_menu_keeps_actions_and_icon_across_translated_labels(self):
        host=QWidget();layout=QHBoxLayout(host)
        button=ChromeButton('▦ START  ▾',host);layout.addWidget(button)
        menu=QMenu(host);triggered=[]
        action=menu.addAction('Original action',lambda:triggered.append('called'))
        original_key=button.property('bb_english')
        try:
            self.assertFalse(button.icon().isNull())
            button.setMenu(menu);host.show()
            self.assertFalse(button.icon().isNull())
            for text in ('▦ ПУСК  ▾','▦ START  ▾','▦ СПРАВКА  ▾'):
                button.setText(text);self.app.processEvents()
                self.assertNotIn('▾',button.text())
                self.assertFalse(button.icon().isNull())
                self.assertIs(button.menu(),menu)
                self.assertEqual(button.menu().actions(),[action])
                self.assertEqual(button.property('bb_english'),original_key)
                self.assertGreaterEqual(button.minimumSizeHint().width(),
                    button.fontMetrics().horizontalAdvance(button.text())+60)
            action.trigger();self.assertEqual(triggered,['called'])
        finally:
            host.close()

    def test_plain_controls_are_not_reinterpreted_as_menu_commands(self):
        button=ChromeButton('Regular text ▾')
        try:
            self.assertIsNone(button.menu())
            self.assertEqual(button.text(),'Regular text ▾')
            button.setText('Обычный текст ▾')
            self.assertEqual(button.text(),'Обычный текст ▾')
            self.assertTrue(button.icon().isNull())
        finally:
            button.close()


if __name__=='__main__':unittest.main()
