"""Human-first resource comparison; machine fields remain an explicit choice."""
from __future__ import annotations

LABELS={
 'cpu_seconds':('CPU time','CPU-время'),'rss_peak_bytes':('Peak RSS','Пик RSS'),
 'rss_delta_bytes':('RSS change','Изменение RSS'),'private_peak_bytes':('Peak private memory','Пик private memory'),
 'private_delta_bytes':('Private memory change','Изменение private memory'),
 'handles_peak':('Peak handles','Пик handles'),'handles_delta':('Handle change','Изменение handles'),
 'read_bytes':('Bytes read','Прочитано'),'write_bytes':('Bytes written','Записано'),
 'ui_timeouts':('Observed UI timeout episodes','Наблюдавшиеся эпизоды неответа UI'),
 'uss_peak_bytes':('Peak USS','Пик USS'),'uss_delta_bytes':('USS change','Изменение USS'),
 'read_ops':('Read operations','Операции чтения'),'write_ops':('Write operations','Операции записи'),
 'threads_peak':('Peak threads','Пик количества потоков'),'sampling_gaps':('Sampling gaps','Разрывы опроса'),
 'observation_errors':('Recorded sensor errors','Записанные ошибки датчиков')}


def comparison_text(result,language):
    ru=language=='RU'
    lines=['Сравнение измерений действий' if ru else 'Action measurement comparison',
        ('Условия совпадают.' if ru else 'Recorded conditions match.') if result.get('comparable_context') else
        ('Условия различаются или заполнены не полностью: ' if ru else 'Conditions differ or are incomplete: ')+', '.join(result.get('context_mismatches',[])),
        '']
    if result.get('context_warnings'):
        lines.append(('Не все метаданные условий записаны: ' if ru else 'Some context metadata was not recorded: ')+', '.join(result['context_warnings']))
    def value(v,unit):
        if v is None:return 'не наблюдалось' if ru else 'not observed'
        if unit=='bytes':return f'{v/1048576:.3g} MiB'
        return f'{v:.4g}'+(' s' if unit=='seconds' else '')
    for key,row in result.get('resource_comparison',{}).items():
        name=LABELS.get(key,(key,key))[int(ru)]
        lines.append(name+': '+value(row.get('before_median'),row['unit'])+' → '+value(row.get('after_median'),row['unit']))
        delta=value(row.get('absolute_delta'),row['unit'])
        percent=row.get('percent_delta')
        lines.append(f'  Δ {delta}'+(f' ({percent:+.2f}%)' if percent is not None else '')+
            f" · N {row.get('before_observed_repeats',0)} / {row.get('after_observed_repeats',0)}")
        if not row.get('sufficient_repeats'):lines.append('  Недостаточно повторений.' if ru else '  Insufficient repetitions.')
    lines.extend(['','Медианы рассчитаны по доступным парам измерений внутри действия. Пропуски не равны нулю. '
        'Короткие действия могут не содержать пары измерений. Ускорение и причина не доказаны.' if ru else
        'Medians use available counter pairs inside each action. Missing is not zero. Short actions may contain no pair. '
        'Speedup and causality are not established.'])
    return '\n'.join(lines)
