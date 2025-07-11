-- name: GetAllFiles :many
select * from files;

-- name: GetFileByID :one
select * from files where id = ?;

-- name: GetFileByName :one
select * from files where name = ?;

-- name: GetFileOriginalNameByNanoId :one
select * from files where name = ?;

-- name: GetFileIdByNanoId :one
select * from files where name = ?;

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
    u.id = ?
AND
    s.id = ?
AND
    f.deleted_at IS NULL
ORDER BY
    f.created_at DESC
LIMIT ? OFFSET ?;

-- name: GetFileIdsFromUserStore :many
SELECT f.id AS file_id
FROM files f
JOIN file_store fs ON f.id = fs.fileId
JOIN user_store us ON fs.storeId = us.storeId
WHERE us.storeId = ? and us.userId = ?;

-- name: IsOwner :one
SELECT CAST(EXISTS (
    SELECT 1
    FROM users u
    JOIN user_store us ON u.id = us.userId
    JOIN stores s ON us.storeId = s.id
    JOIN file_store fs ON s.id = fs.storeId
    JOIN files f ON fs.fileId = f.id
    WHERE u.username = ? AND f.name = ?
) AS BOOLEAN); -- Add CAST(... AS BOOLEAN)

-- name: CreateFile :one
insert into files (name, original_name, content_type, md5) values (?, ?, ?, ?) returning *;

-- name: RenameFile :one
update files set name = ? where id = ? returning *;

-- name: DeleteFileByNanoId :exec
delete from files where name = ?;

-- name: DeleteFileById :exec
update files set deleted_at = CURRENT_TIMESTAMP where id = ?;
-- delete from files where id = ?;
