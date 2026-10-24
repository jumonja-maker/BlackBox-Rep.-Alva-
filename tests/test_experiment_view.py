import unittest
from blackbox_universal.experiment_view import comparison_text

class ComparisonPresentationTests(unittest.TestCase):
    def test_zero_and_unknown_are_visibly_different_in_both_languages(self):
        result={'comparable_context':False,'context_mismatches':['workload'],
            'resource_comparison':{'cpu_seconds':{'unit':'seconds','before_median':0,'after_median':None,
                'absolute_delta':None,'percent_delta':None,'before_observed_repeats':2,'after_observed_repeats':0,
                'sufficient_repeats':False}}}
        for language,unknown in (('RU','не наблюдалось'),('EN','not observed')):
            text=comparison_text(result,language)
            self.assertIn('0 s',text);self.assertIn(unknown,text);self.assertIn('N 2 / 0',text)
            self.assertIn('workload',text)
