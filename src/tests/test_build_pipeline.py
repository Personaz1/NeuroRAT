import os

def test_stage0_bin_exists():
    """Проверяем, что build/stage0.bin существует"""
    stage0_path = os.path.join(os.getcwd(), 'build', 'stage0.bin')
    assert os.path.isfile(stage0_path), f"stage0.bin не найден по пути: {stage0_path}"

def test_stage0_contains_markers():
    """Проверяем наличие маркеров в бинарнике stage0.bin"""
    data = open('build/stage0.bin', 'rb').read()
    # little-endian маркеры
    marker1 = b'\xbe\xba\xfe\xca\xef\xbe\xad\xde'  # 0xDEADBEEFCAFEBABE
    marker2 = b'\x0d\xf0\xbe\xba\xce\xfa\xed\xfe'  # 0xFEEDFACEBABEF00D
    marker3 = b'\xde\xc0\xad\xde\xba\xad\xc0\xde'  # 0xDEADC0DEBAADC0DE
    assert marker1 in data, 'Marker1 не найден в stage0.bin'
    assert marker2 in data, 'Marker2 не найден в stage0.bin'
    assert marker3 in data, 'Marker3 не найден в stage0.bin'

def test_phantom_payload_exists():
    """Проверяем, что build/phantom_payload.bin существует"""
    phantom_path = os.path.join(os.getcwd(), 'build', 'phantom_payload.bin')
    assert os.path.isfile(phantom_path), f"phantom_payload.bin не найден по пути: {phantom_path}"

def test_phantom_payload_size_greater_than_stage0():
    """Проверяем, что размер phantom_payload.bin больше, чем stage0.bin"""
    size_stage0 = os.path.getsize('build/stage0.bin')
    size_phantom = os.path.getsize('build/phantom_payload.bin')
    assert size_phantom > size_stage0, f"Размер phantom_payload.bin ({size_phantom}) не больше, чем stage0.bin ({size_stage0})" 