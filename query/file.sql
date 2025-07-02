-- name: GetAllFiles :many
select * from files;

-- name: GetFileByID :one
select * from files where id = $1;

-- name: GetFileByName :one
select * from files where name = $1;

-- name: GetFileOriginalNameByNanoId :one
select * from files where name = $1;

-- name: GetFileIdByNanoId :one
select * from files where name = $1;

-- name: GetFilesPaginated :many
SELECT 
    f.id AS file_id,
    f.name AS file_name,
    f.original_name AS file_original_name,
    f.content_type AS file_content_type,
    f.md5 AS file_md5,
    f.created_at AS file_created_at
FROM 
    users u
JOIN 
    user_store us ON u.id = us.userId
JOIN 
    stores s ON us.storeId = s.id
JOIN 
    file_store fs ON s.id = fs.storeId
JOIN 
    files f ON fs.fileId = f.id
WHERE 
    u.id = $3
AND 
    s.id = $4
AND
    f.deleted_at IS NULL
ORDER BY 
    f.created_at DESC
LIMIT $1 OFFSET $2;

-- name: GetFileIdsFromUserStore :many
SELECT f.id AS file_id
FROM files f
JOIN file_store fs ON f.id = fs.fileId
JOIN user_store us ON fs.storeId = us.storeId
WHERE us.storeId = $1 and us.userId = $2;

-- name: IsOwner :one
SELECT EXISTS (
    SELECT 1
    FROM users u
    JOIN user_store us ON u.id = us.userId
    JOIN stores s ON us.storeId = s.id
    JOIN file_store fs ON s.id = fs.storeId
    JOIN files f ON fs.fileId = f.id
    WHERE u.username = $1 AND f.name = $2 
);

-- name: CreateFile :one
insert into files (name, original_name, content_type, md5) values ($1, $2, $3, $4) returning *;

-- name: RenameFile :one
update files set name = $2 where id = $1 returning *;

-- name: DeleteFileByNanoId :exec
delete from files where name = $1;

-- name: DeleteFileById :exec
update files set deleted_at = now() where id = $1;
-- delete from files where id = $1;
