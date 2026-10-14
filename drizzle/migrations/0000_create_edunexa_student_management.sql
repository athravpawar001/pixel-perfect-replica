CREATE TYPE public.app_role AS ENUM ('admin', 'user');

CREATE TABLE public.user_roles (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE, role public.app_role NOT NULL, UNIQUE (user_id, role));
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role public.app_role) RETURNS BOOLEAN LANGUAGE SQL STABLE SECURITY DEFINER SET search_path = public AS $$ SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role) $$;
REVOKE ALL ON FUNCTION public.has_role(UUID, public.app_role) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.has_role(UUID, public.app_role) TO authenticated, service_role;
CREATE POLICY "Users can read their own roles" ON public.user_roles FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

CREATE TABLE public.profiles (id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE, full_name TEXT NOT NULL DEFAULT '' CHECK (char_length(full_name) <= 120), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
GRANT SELECT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own profile or administrators read any" ON public.profiles FOR SELECT TO authenticated USING (id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users update own profile" ON public.profiles FOR UPDATE TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());

CREATE TABLE public.courses (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 120), code TEXT NOT NULL CHECK (char_length(trim(code)) BETWEEN 1 AND 24), description TEXT CHECK (char_length(description) <= 1000), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (code));
GRANT SELECT, INSERT, UPDATE, DELETE ON public.courses TO authenticated;
GRANT ALL ON public.courses TO service_role;
ALTER TABLE public.courses ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Administrators manage courses" ON public.courses FOR ALL TO authenticated USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE TABLE public.students (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), roll_number TEXT NOT NULL CHECK (char_length(trim(roll_number)) BETWEEN 1 AND 32), full_name TEXT NOT NULL CHECK (char_length(trim(full_name)) BETWEEN 1 AND 120), email TEXT CHECK (email IS NULL OR char_length(email) <= 254), phone TEXT CHECK (phone IS NULL OR char_length(phone) <= 32), course_id UUID NOT NULL REFERENCES public.courses(id) ON DELETE RESTRICT, enrollment_date DATE NOT NULL DEFAULT CURRENT_DATE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (roll_number));
GRANT SELECT, INSERT, UPDATE, DELETE ON public.students TO authenticated;
GRANT ALL ON public.students TO service_role;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Administrators manage students" ON public.students FOR ALL TO authenticated USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE INDEX students_course_id_idx ON public.students(course_id);
CREATE INDEX students_enrollment_date_idx ON public.students(enrollment_date DESC);

CREATE TABLE public.subjects (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), course_id UUID NOT NULL REFERENCES public.courses(id) ON DELETE RESTRICT, name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 120), code TEXT NOT NULL CHECK (char_length(trim(code)) BETWEEN 1 AND 24), max_marks NUMERIC(7,2) NOT NULL CHECK (max_marks > 0), passing_marks NUMERIC(7,2) NOT NULL CHECK (passing_marks >= 0 AND passing_marks <= max_marks), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (course_id, code));
GRANT SELECT, INSERT, UPDATE, DELETE ON public.subjects TO authenticated;
GRANT ALL ON public.subjects TO service_role;
ALTER TABLE public.subjects ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Administrators manage subjects" ON public.subjects FOR ALL TO authenticated USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE INDEX subjects_course_id_idx ON public.subjects(course_id);

CREATE TABLE public.assessments (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), course_id UUID NOT NULL REFERENCES public.courses(id) ON DELETE RESTRICT, name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 120), term TEXT NOT NULL DEFAULT '' CHECK (char_length(term) <= 80), is_published BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (course_id, name, term));
GRANT SELECT, INSERT, UPDATE, DELETE ON public.assessments TO authenticated;
GRANT ALL ON public.assessments TO service_role;
ALTER TABLE public.assessments ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Administrators manage assessments" ON public.assessments FOR ALL TO authenticated USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE INDEX assessments_course_id_idx ON public.assessments(course_id);

CREATE TABLE public.marks (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), student_id UUID NOT NULL REFERENCES public.students(id) ON DELETE RESTRICT, subject_id UUID NOT NULL REFERENCES public.subjects(id) ON DELETE RESTRICT, assessment_id UUID NOT NULL REFERENCES public.assessments(id) ON DELETE RESTRICT, marks_obtained NUMERIC(7,2) NOT NULL CHECK (marks_obtained >= 0), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (student_id, subject_id, assessment_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON public.marks TO authenticated;
GRANT ALL ON public.marks TO service_role;
ALTER TABLE public.marks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Administrators manage marks" ON public.marks FOR ALL TO authenticated USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE INDEX marks_student_id_idx ON public.marks(student_id);
CREATE INDEX marks_assessment_id_idx ON public.marks(assessment_id);
CREATE INDEX marks_subject_id_idx ON public.marks(subject_id);

CREATE OR REPLACE FUNCTION public.touch_updated_at() RETURNS TRIGGER LANGUAGE plpgsql SET search_path = public AS $$ BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;
CREATE OR REPLACE FUNCTION public.create_profile_for_new_user() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$ BEGIN INSERT INTO public.profiles (id, full_name) VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', '')) ON CONFLICT (id) DO NOTHING; RETURN NEW; END; $$;
CREATE TRIGGER auth_user_profile_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.create_profile_for_new_user();

CREATE OR REPLACE FUNCTION public.validate_marks_record() RETURNS TRIGGER LANGUAGE plpgsql SET search_path = public AS $$ DECLARE ac UUID; sc UUID; stc UUID; mx NUMERIC(7,2); published BOOLEAN; BEGIN IF TG_OP = 'DELETE' THEN SELECT is_published INTO published FROM public.assessments WHERE id = OLD.assessment_id; IF published THEN RAISE EXCEPTION 'Published assessment marks cannot be removed.'; END IF; RETURN OLD; END IF; SELECT course_id, is_published INTO ac, published FROM public.assessments WHERE id = NEW.assessment_id; SELECT course_id, max_marks INTO sc, mx FROM public.subjects WHERE id = NEW.subject_id; SELECT course_id INTO stc FROM public.students WHERE id = NEW.student_id; IF ac IS NULL OR sc IS NULL OR stc IS NULL THEN RAISE EXCEPTION 'Student, subject, or assessment not found.'; END IF; IF published THEN RAISE EXCEPTION 'Published assessment marks cannot be changed.'; END IF; IF ac <> sc OR ac <> stc THEN RAISE EXCEPTION 'Student, subject, and assessment must belong to the same course.'; END IF; IF NEW.marks_obtained > mx THEN RAISE EXCEPTION 'Marks cannot exceed the subject maximum.'; END IF; RETURN NEW; END; $$;
CREATE TRIGGER marks_validate_before_write BEFORE INSERT OR UPDATE OR DELETE ON public.marks FOR EACH ROW EXECUTE FUNCTION public.validate_marks_record();

CREATE OR REPLACE FUNCTION public.validate_assessment_publication() RETURNS TRIGGER LANGUAGE plpgsql SET search_path = public AS $$ DECLARE expected BIGINT; actual BIGINT; BEGIN IF NEW.is_published AND NOT OLD.is_published THEN SELECT count(*) INTO expected FROM public.students st CROSS JOIN public.subjects su WHERE st.course_id = NEW.course_id AND su.course_id = NEW.course_id; SELECT count(*) INTO actual FROM public.marks m JOIN public.students st ON st.id = m.student_id JOIN public.subjects su ON su.id = m.subject_id WHERE m.assessment_id = NEW.id AND st.course_id = NEW.course_id AND su.course_id = NEW.course_id; IF expected = 0 OR actual <> expected THEN RAISE EXCEPTION 'Add marks for every student and subject before publishing results.'; END IF; END IF; RETURN NEW; END; $$;
CREATE TRIGGER assessment_publication_check BEFORE UPDATE OF is_published ON public.assessments FOR EACH ROW EXECUTE FUNCTION public.validate_assessment_publication();

CREATE OR REPLACE FUNCTION public.protect_published_records() RETURNS TRIGGER LANGUAGE plpgsql SET search_path = public AS $$ BEGIN IF TG_TABLE_NAME = 'subjects' AND EXISTS (SELECT 1 FROM public.marks m JOIN public.assessments a ON a.id = m.assessment_id WHERE m.subject_id = OLD.id AND a.is_published) THEN RAISE EXCEPTION 'Subjects with published results cannot be modified or removed.'; END IF; IF TG_TABLE_NAME = 'students' AND EXISTS (SELECT 1 FROM public.marks m JOIN public.assessments a ON a.id = m.assessment_id WHERE m.student_id = OLD.id AND a.is_published) THEN RAISE EXCEPTION 'Students with published results cannot be modified or removed.'; END IF; IF TG_TABLE_NAME = 'students' AND TG_OP = 'UPDATE' AND NEW.course_id <> OLD.course_id AND EXISTS (SELECT 1 FROM public.marks WHERE student_id = OLD.id) THEN RAISE EXCEPTION 'A student with recorded marks cannot be reassigned to another course.'; END IF; IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW; END; $$;
CREATE TRIGGER subject_published_result_guard BEFORE UPDATE OR DELETE ON public.subjects FOR EACH ROW EXECUTE FUNCTION public.protect_published_records();
CREATE TRIGGER student_published_result_guard BEFORE UPDATE OR DELETE ON public.students FOR EACH ROW EXECUTE FUNCTION public.protect_published_records();

CREATE TRIGGER profiles_touch_updated_at BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
CREATE TRIGGER courses_touch_updated_at BEFORE UPDATE ON public.courses FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
CREATE TRIGGER students_touch_updated_at BEFORE UPDATE ON public.students FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
CREATE TRIGGER subjects_touch_updated_at BEFORE UPDATE ON public.subjects FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
CREATE TRIGGER assessments_touch_updated_at BEFORE UPDATE ON public.assessments FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
CREATE TRIGGER marks_touch_updated_at BEFORE UPDATE ON public.marks FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();