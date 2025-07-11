-- name: AddFileToStore :exec
insert into file_store (fileId, storeId) values (?, ?);

-- name: RemoveFileFromStore :exec
delete from file_store where fileId = ? and storeId = ?;

-- name: GetAllFilesFromStore :many
select * from file_store where id = ?;

-- name: MoveFileToStore :exec
update file_store set storeId = ? where fileid = ? and storeId = ?;
