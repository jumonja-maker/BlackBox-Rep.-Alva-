import os
import unittest
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from PySide6.QtWidgets import QApplication
from blackbox_universal.research_panel import EvidenceTimeline

class TimelineGapPresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])
    def test_unknown_is_a_line_break_but_real_zero_is_retained(self):
        w=EvidenceTimeline();w.set_data({'range_ms':[0,5000],'chart':[
            {'elapsed_ms':0,'cpu_percent':5},{'elapsed_ms':1000,'cpu_percent':None},
            {'elapsed_ms':2000,'cpu_percent':0},{'elapsed_ms':3000,'cpu_percent':10}]})
        self.assertEqual(w.curve_segments(),[[(0,5.0)],[(2000,0.0),(3000,10.0)]])
    def test_normalized_counter_pair_segments_are_not_joined_across_gap(self):
        w=EvidenceTimeline();w.set_data({'range_ms':[0,5000],'chart':[],
            'normalised_interval':{'metadata':{'monotonic_origin_ns':1000000000},'timeline':{'tracks':{
                'cpu_interval_percent':[{'time_ns':2000000000,'value':10,'segment':1},
                    {'time_ns':5000000000,'value':20,'segment':2}]}}}})
        self.assertEqual(w.curve_segments(),[[(1000.0,10.0)],[(4000.0,20.0)]])
    def test_nonfinite_imported_values_are_not_drawn_as_data(self):
        w=EvidenceTimeline();w.set_data({'range_ms':[0,5000],'chart':[
            {'elapsed_ms':0,'cpu_percent':float('inf')},{'elapsed_ms':1,'cpu_percent':float('nan')}]})
        self.assertEqual(w.curve_segments(),[])
