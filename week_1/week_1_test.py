from week_1.student_id import student_id


def test_student_id():
    # TODO: 본인 학번을 우측에 적으세요.
    assert student_id() == '본인 학번'


def test_student_id_is_string():
    assert type(student_id()) == str
