-- name: AddFileToStore :exec
insert into file_store (fileId, storeId) values ($1, $2);

-- name: RemoveFileFromStore :exec
delete from file_store where fileId = $1 and storeId = $2;

-- name: GetAllFilesFromStore :many
select * from file_store where id = $1;

-- name: MoveFileToStore :exec
update file_store set storeId = $3 where fileid = $1 and storeId = $2;
