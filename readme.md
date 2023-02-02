```postgresql
create function crypt_password(password char varying default null) returns character varying
    language plpgsql as
$$
BEGIN
    if password is null then
        raise exception 'Password can not be null' using hint = 'User registration';
    end if;
    return utils.crypt(password, utils.gen_salt('bf', 4));
END
$$;-- crypt given password


create function match_password(password char varying, coded_password char varying) returns bool
    language plpgsql as
$$
BEGIN
    if password is null then
        raise exception 'Password can not be null' using hint = 'User registration';
    end if;
    if coded_password is null then
        raise exception 'Coded password can not be null' using hint = 'User registration',
            detail = 'match_password function';
    end if;
    return coded_password = utils.crypt(password, coded_password);
END
$$;--matches given password and original password if matches then return true or return false


create function check_email(u_email varchar) returns bool
    language plpgsql as
$$
DECLARE
    em      varchar;
    pattern varchar := '^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-]+)(\.[a-zA-Z]{2,5}){1,2}$';
BEGIN
    if u_email is null or trim(u_email) ilike '' then
        raise exception 'Email can not be null or empty' using hint = 'Check email';
    end if;
    return u_email ~* pattern;
END
$$;-- checks email is valid or invalid

create function check_username(i_username varchar) returns bool
    language plpgsql as
$$
BEGIN
    if i_username is null then
        raise exception 'Username can not be null';
    end if;
    return true;
END
$$;-- checks username is valid or invalid


create function create_user(data_params text) returns bigint
    language plpgsql as
$$
DECLARE
    json_data json;
    new_id    bigint;
    c_dto     utils.create_user_dto;
    t_user    record;
BEGIN
    if data_params is null or data_params = '{}'::text or trim(data_params) = '' then
        raise exception 'Parameters can not be null or empty' using message = 'Check parameters';
    end if;

    json_data := data_params::json;
    c_dto := mapper.json_to_create_user_dto(json_data);

    if c_dto.full_name is null or trim(c_dto.full_name) ilike '' then
        raise exception 'Full name can not be null or empty';
    end if;

    if helper.check_email(c_dto.email) is false then
        raise exception 'Wrong email format' using detail = 'Email will be as: example@gmail.com';
    end if;
    select * into t_user from public.users usr where usr.email ilike c_dto.email;
    if FOUND then
        raise exception 'User with email % already exist',t_user.email;
    end if;

    if c_dto.password is null then
        raise exception 'Password can not be null';
    end if;

    if c_dto.language_id is null then
        raise exception 'Language id can not be null';
    end if;
    if not exists(select t.id from public.language t where t.id = c_dto.language_id) then
        raise exception 'Non existent language id' using hint = 'See languages';
    end if;

    if helper.check_username(c_dto.username) is false then
        raise exception 'Wrong username';
    end if;
    select * into t_user from public.users usr where usr.username ilike c_dto.username;
    if FOUND then
        raise exception 'User with username % already exist',t_user.username;
    end if;

    insert into public.users(username, password, fullname, email, language_id)
    VALUES (c_dto.username,
            helper.crypt_password(c_dto.password),
            c_dto.full_name,
            c_dto.email,
            c_dto.language_id)
    returning id into new_id;
    return new_id;
END
$$;-- creates user if all right or else return exception

create procedure is_active(IN i_user_id bigint DEFAULT NULL::bigint)
    language plpgsql as
$$
begin
    if i_user_id is null then
        raise exception 'User not found with this % id',i_user_id;
    end if;
    if not exists(select * from public.users u where u.id = i_user_id and is_deleted = 0) then
        raise exception 'User not found with % this id',i_user_id;
    end if;
end;
$$; -- checks users they are active or no

create function has_role(userid bigint DEFAULT NULL::bigint,
                         i_role text DEFAULT NULL::text) returns boolean
    language plpgsql as
$$
declare
    t_user record;
BEGIN
    if userid is null or i_role is null then
        return false;
    end if;
    select * into t_user from public.users t where t.is_deleted = 0 and t.id = userid;
    return FOUND and t_user.role::text ilike i_role::text;
END
$$;-- checks user whether they have given role or no


create function delete_user(user_id bigint, session_user_id bigint) returns bool
    language plpgsql as
$$
DECLARE
    t_user record;
BEGIN
    call helper.is_active(user_id);
    call helper.is_active(session_user_id);

    select * into t_user from public.users usr where session_user_id = usr.id;
    if (t_user.role = 'SUPER_ADMIN' or t_user.id = user_id) is false then
        raise exception 'Permission denied' using hint = 'Super admin or her/his own can delete';
    end if;
    update public.users set is_deleted = 1 where id = user_id;
    return true;
END
$$; -- delete user if user is admin or his/her own


create function update_user(data_params text, session_user_id bigint) returns bool
    language plpgsql as
$$
DECLARE
    json_data json;
    t_user    record;
    dto       utils.update_user_dto;
    lang_id   smallint;
BEGIN
    call helper.is_active(session_user_id);

    if data_params is null or data_params = '{}'::text then
        raise exception 'Data parameters can not be null or empty';
    end if;

    json_data := data_params::json;
    dto := mapper.json_to_update_user_dto(json_data);

    call helper.is_active(dto.id);

    if (dto.id = session_user_id or helper.has_role(session_user_id, 'SUPER_ADMIN')) is false then
        raise exception 'Permission denied';
    end if;

    select * into t_user from public.users t where t.is_deleted = 0 and t.id = dto.id;
    if not FOUND then
        raise exception 'User not found by id ''%''',dto.id;
    end if;

    if dto.username is null then
        dto.username := t_user.username;
    end if;
    if dto.full_name is null then
        dto.full_name := t_user.fullname;
    end if;
    if dto.password is null then
        dto.password := t_user.password;
    end if;
    if dto.email is null then
        dto.email := t_user.email;
    end if;
    if dto.role is null then
        dto.role := t_user.role;
    end if;
    if dto.role::text != t_user.role::text then
        if helper.has_role(session_user_id, 'SUPER_ADMIN') is false then
            raise exception 'Permission denied' using detail = 'Super admin can change users role';
        end if;
    end if;

    if dto.language_id is null then
        dto.language_id := t_user.language_id;
    end if;

    select tl.id into lang_id from public.language tl where tl.id = dto.language_id;
    if not FOUND then
        raise exception 'Wrong language id' using detail = 'User update error';
    end if;
    if helper.check_email(dto.email) is false then
        raise exception 'Wrong email format % ',dto.email using detail = 'Email will be as: example@gmail.com';
    end if;
    select * into t_user from public.users usr where usr.email ilike dto.email;
    if FOUND and t_user.id != dto.id then
        raise exception 'User with email % already exist',t_user.email;
    end if;
    if helper.check_username(dto.username) is false then
        raise exception 'Wrong username';
    end if;
    select * into t_user from public.users usr where usr.username ilike dto.username;
    if FOUND and t_user.id != dto.id then
        raise exception 'User with username % already exist',t_user.username;
    end if;

    if helper.has_role(session_user_id, 'SUPER_ADMIN') then
        update public.users
        set fullname    = dto.full_name,
            username    = dto.username,
            password    = dto.password,
            email       = dto.email,
            language_id = dto.language_id,
            role        = cast(dto.role as utils.user_role)
        where id = dto.id;
    else
        update public.users
        set username    = dto.username,
            password    = dto.password,
            fullname    = dto.full_name,
            language_id = dto.language_id,
            email       = dto.email
        where id = dto.id;
    end if;
    return true;
END
$$;-- updates user with given fields  if all right or else return exception 

create function get_user(i_user_id bigint default null) returns text
    language plpgsql as
$$
begin
    return coalesce(((select (json_build_object(
            'id', t.id,
            'fullname', t.fullname,
            'username', t.username,
            'email', t.email,
            'role', t.role,
            'created_at', t.created_at,
            'language_id', t."language_id"
        ))
                      from public.users t
                      where t.is_deleted = 0
                        and t.id = i_user_id)::text), '[]');
end
$$;-- get user by userId

create function get_users() returns text
    language plpgsql as
$$
begin
    return coalesce(((select json_agg(json_build_object(
            'id', t.id,
            'fullname', t.fullname,
            'username', t.username,
            'email', t.email,
            'role', t.role,
            'created_at', t.created_at,
            'language_id', t."language_id"
        ))
                      from public.users t
                      where t.is_deleted = 0)::text), '[]');
end
$$;-- to get all users from database
```